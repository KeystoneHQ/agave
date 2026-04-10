use {
    crate::{
        locator::Manufacturer,
        remote_wallet::{RemoteWallet, RemoteWalletError, RemoteWalletInfo},
    },
    console::Emoji,
    hex,
    semver::Version as FirmwareVersion,
    serde_json,
    solana_derivation_path::DerivationPath,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    std::{convert::TryFrom, fmt},
    ur_parse_lib::keystone_ur_decoder::probe_decode,
    ur_parse_lib::keystone_ur_encoder::probe_encode,
    ur_registry::crypto_key_path::{CryptoKeyPath, PathComponent},
    ur_registry::extend::crypto_multi_accounts::CryptoMultiAccounts,
    ur_registry::extend::key_derivation::KeyDerivationCall,
    ur_registry::extend::key_derivation_schema::{Curve, KeyDerivationSchema},
    ur_registry::extend::qr_hardware_call::{
        CallParams, CallType, HardWareCallVersion, QRHardwareCall,
    },
    ur_registry::solana::sol_sign_request::{SignType, SolSignRequest},
    ur_registry::solana::sol_signature::SolSignature,
    ur_registry::traits::RegistryItem,
};

static CHECK_MARK: Emoji = Emoji("✅ ", "");

const REQUEST_ID: u16 = 0xACE0;
const HID_TAG: u8 = 0xAA;

/// Keystone vendor ID
const KEYSTONE_VID: u16 = 0x1209;
/// Keystone product ID
const KEYSTONE_PID: u16 = 0x3001;

const LEDGER_TRANSPORT_HEADER_LEN: usize = 5;
const HID_PACKET_SIZE: usize = 64;

// Windows adds a prefix byte to HID packets
#[cfg(target_os = "windows")]
const HID_PREFIX_ZERO: usize = 1;
#[cfg(not(target_os = "windows"))]
const HID_PREFIX_ZERO: usize = 0;

// JSON response field names
const JSON_FIELD_PUBKEY: &str = "pubkey";
const JSON_FIELD_FIRMWARE_VERSION: &str = "firmwareVersion";
const JSON_FIELD_WALLET_MFP: &str = "walletMFP";

// Error messages
const ERROR_INVALID_JSON: &str = "Invalid JSON response";
const ERROR_MISSING_FIELD: &str = "Missing required field";
const ERROR_SIGNATURE_SIZE: &str = "Signature packet size mismatch";
const ERROR_KEY_SIZE: &str = "Key packet size mismatch";

#[derive(Debug, Clone, Copy, PartialEq)]
enum CommandType {
    CmdEchoTest = 0x01,
    CmdResolveUR = 0x02,
    CmdCheckLockStatus = 0x03,
    CmdExportAddress = 0x04,
    CmdGetDeviceInfo = 0x05,
    CmdGetDeviceUSBPubkey = 0x06,
}

impl CommandType {
    fn is_valid_command(value: u16) -> bool {
        matches!(value, 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06)
    }
}

const WEBUSB_PROTOCOL_HEADER: u8 = 0x6B;
const WEBUSB_PROTOCOL_VERSION: u8 = 0;

fn webusb_service_command(command: CommandType) -> (u8, u8) {
    match command {
        // SERVICE_ID_DEVICE_INFO + COMMAND_ID_DEVICE_INFO_BASIC
        CommandType::CmdGetDeviceInfo => (1, 1),
        // Keep compatibility for other calls until full service mapping is finalized.
        _ => (1, command as u8),
    }
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Keystone hardware wallet device
pub struct KeystoneWallet {
    pub device: rusb::Device<rusb::Context>,
    pub handle: rusb::DeviceHandle<rusb::Context>,
    pub interface_number: u8,
    pub endpoint_out: u8,
    pub endpoint_in: u8,
    pub transfer_type: rusb::TransferType,
    pub pretty_path: String,
    pub version: FirmwareVersion,
    pub mfp: Option<[u8; 4]>,
}

impl fmt::Debug for KeystoneWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeystoneWallet")
    }
}

impl KeystoneWallet {
    pub fn new(
        device: rusb::Device<rusb::Context>,
        handle: rusb::DeviceHandle<rusb::Context>,
    ) -> Result<Self, RemoteWalletError> {
        let (interface_number, endpoint_out, endpoint_in, transfer_type) =
            Self::discover_usb_io(&device)?;

        // Best effort: detach kernel driver where supported.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let _ = handle.detach_kernel_driver(interface_number);
        }

        handle.claim_interface(interface_number).map_err(|e| {
            RemoteWalletError::Hid(format!(
                "Failed to claim USB interface {interface_number}: {e}"
            ))
        })?;

        Ok(Self {
            device,
            handle,
            interface_number,
            endpoint_out,
            endpoint_in,
            transfer_type,
            pretty_path: String::default(),
            version: FirmwareVersion::new(0, 0, 0),
            mfp: None,
        })
    }

    fn discover_usb_io(
        device: &rusb::Device<rusb::Context>,
    ) -> Result<(u8, u8, u8, rusb::TransferType), RemoteWalletError> {
        let config = device
            .active_config_descriptor()
            .or_else(|_| device.config_descriptor(0))
            .map_err(|e| {
                RemoteWalletError::Hid(format!("Failed to read USB config descriptor: {e}"))
            })?;

        // Prefer interrupt endpoints (HID-like), fall back to bulk if needed.
        for wanted_type in [rusb::TransferType::Interrupt, rusb::TransferType::Bulk] {
            for interface in config.interfaces() {
                for descriptor in interface.descriptors() {
                    let mut endpoint_out = None;
                    let mut endpoint_in = None;
                    for ep in descriptor.endpoint_descriptors() {
                        if ep.transfer_type() != wanted_type {
                            continue;
                        }
                        match ep.direction() {
                            rusb::Direction::Out => {
                                endpoint_out.get_or_insert(ep.address());
                            }
                            rusb::Direction::In => {
                                endpoint_in.get_or_insert(ep.address());
                            }
                        }
                    }
                    if let (Some(out), Some(inn)) = (endpoint_out, endpoint_in) {
                        return Ok((descriptor.interface_number(), out, inn, wanted_type));
                    }
                }
            }
        }

        Err(RemoteWalletError::Protocol(
            "No suitable USB IN/OUT endpoints found",
        ))
    }

    /// Write data to device with Keystone USB transport framing
    fn write(&self, command: CommandType, data: &[u8]) -> Result<(), RemoteWalletError> {
        let (service_id, command_id) = webusb_service_command(command);
        let payload_len = data.len();

        // FrameHead_t (packed, little-endian u16 fields):
        // head(1), protocolVersion(1), packetIndex(2), serviceId(1), commandId(1), flag(2), length(2)
        const HEAD_LEN: usize = 10;
        const CRC_LEN: usize = 4;
        let mut frame = Vec::with_capacity(HEAD_LEN + payload_len + CRC_LEN);
        frame.push(WEBUSB_PROTOCOL_HEADER);
        frame.push(WEBUSB_PROTOCOL_VERSION);
        frame.extend_from_slice(&0u16.to_le_bytes()); // packetIndex
        frame.push(service_id);
        frame.push(command_id);
        frame.extend_from_slice(&0x0002u16.to_le_bytes()); // isHost=1, ack=0
        frame.extend_from_slice(&(payload_len as u16).to_le_bytes());
        frame.extend_from_slice(data);

        let crc = crc32_ieee(&frame);
        frame.extend_from_slice(&crc.to_le_bytes());

        println!(
            "[Keystone TX] command={:?}, svc={}, cmdId={}, payload_len={}, frame_hex: {}",
            command,
            service_id,
            command_id,
            payload_len,
            hex::encode(&frame)
        );

        self.device_write(&frame)?;
        Ok(())
    }

    /// Read data from device with Keystone USB transport parsing
    fn read(&self) -> Result<Vec<u8>, RemoteWalletError> {
        let mut result_data = Vec::new();
        let mut expected_next_seq: Option<u16> = None;
        let mut total_packets: u16 = 0;
        let mut received_packets: u16 = 0;

        loop {
            let chunk = self.device_read()?;
            if chunk.len() < 12 {
                return Err(RemoteWalletError::Protocol("Invalid HID packet size"));
            }

            let mut selected: Option<(usize, u16, u16, u16, usize)> = None;
            for offset in [0usize, 1usize] {
                if chunk.len() < offset + 12 {
                    continue;
                }
                let packet = &chunk[offset..];
                let command = u16::from_be_bytes([packet[2], packet[3]]);
                let total_pkt = u16::from_be_bytes([packet[4], packet[5]]);
                let packet_seq = u16::from_be_bytes([packet[6], packet[7]]);
                let size = packet[11] as usize;
                if CommandType::is_valid_command(command)
                    && total_pkt > 0
                    && size <= packet.len().saturating_sub(12)
                {
                    selected = Some((offset, command, total_pkt, packet_seq, size));
                    break;
                }
            }

            let (offset, command, total_pkt, packet_seq, size) = selected
                .ok_or(RemoteWalletError::Protocol("Unable to parse packet header"))?;

            let packet = &chunk[offset..];
            let packet_hex = hex::encode(packet);
            println!(
                "[Keystone RX] off={}, cmd=0x{:04x}, total={}, seq={}, size={}, raw_hex: {}",
                offset, command, total_pkt, packet_seq, size, packet_hex
            );

            if expected_next_seq.is_none() {
                expected_next_seq = Some(packet_seq);
                total_packets = total_pkt;
            }

            if Some(packet_seq) != expected_next_seq {
                return Err(RemoteWalletError::Protocol("Invalid packet sequence"));
            }

            let end = std::cmp::min(12 + size, packet.len());
            result_data.extend_from_slice(&packet[12..end]);

            received_packets += 1;
            expected_next_seq = Some(packet_seq.wrapping_add(1));

            if received_packets >= total_packets {
                break;
            }

            if received_packets >= 0xffff {
                return Err(RemoteWalletError::Protocol(
                    "Maximum sequence number reached",
                ));
            }
        }

        while !result_data.is_empty() && result_data[result_data.len() - 1] == 0x00 {
            result_data.pop();
        }

        if result_data.len() < 2 {
            return Err(RemoteWalletError::Protocol("Response too short"));
        }

        result_data.truncate(result_data.len() - 2);
        Ok(result_data)
    }

    /// Send APDU command and receive JSON response
    fn send_apdu(&self, command: CommandType, data: &[u8]) -> Result<String, RemoteWalletError> {
        self.write(command, data)?;
        let message = self.read()?;
        let message_str = String::from_utf8_lossy(&message);

        // Extract JSON from response
        if let (Some(start), Some(end)) = (message_str.find('{'), message_str.rfind('}')) {
            if start < end {
                let json_str = &message_str[start..=end];
                return Ok(json_str.to_string());
            }
        }

        Ok(message_str.to_string())
    }

    /// Get device firmware version and master fingerprint
    fn get_device_info(&self) -> Result<(FirmwareVersion, Option<[u8; 4]>), RemoteWalletError> {
        let json_str = self.send_apdu(CommandType::CmdGetDeviceInfo, &[])?;
        println!("[Keystone DeviceInfo] raw_json: {}", json_str);
        let json = serde_json::from_str::<serde_json::Value>(&json_str)
            .map_err(|_| RemoteWalletError::Protocol(ERROR_INVALID_JSON))?;

        // Parse firmware version
        let version_str = json
            .get(JSON_FIELD_FIRMWARE_VERSION)
            .and_then(|v| v.as_str())
            .ok_or(RemoteWalletError::Protocol(ERROR_MISSING_FIELD))?;

        let version = FirmwareVersion::parse(version_str)
            .map_err(|_| RemoteWalletError::Protocol("Invalid firmware version"))?;

        // Parse master fingerprint (MFP)
        let mfp = json
            .get(JSON_FIELD_WALLET_MFP)
            .and_then(|v| v.as_str())
            .and_then(|hex_str| {
                let bytes = hex::decode(hex_str).ok()?;
                if bytes.len() == 4 {
                    Some([bytes[0], bytes[1], bytes[2], bytes[3]])
                } else {
                    None
                }
            });

        let mfp_hex = mfp
            .map(hex::encode)
            .unwrap_or_else(|| "<none>".to_string());
        println!(
            "[Keystone DeviceInfo] firmware_version={}, wallet_mfp={}",
            version, mfp_hex
        );

        Ok((version, mfp))
    }

    /// Generate UR-encoded key derivation request for QR code display
    fn generate_hardware_call(
        &self,
        derivation_path: &DerivationPath,
    ) -> Result<String, RemoteWalletError> {
        let key_path = parse_crypto_key_path(derivation_path, self.mfp);
        let schema =
            KeyDerivationSchema::new(key_path, Some(Curve::Ed25519), None, None);
        let schemas = vec![schema];
        let call = QRHardwareCall::new(
            CallType::KeyDerivation,
            CallParams::KeyDerivation(KeyDerivationCall::new(schemas)),
            None,
            HardWareCallVersion::V1,
        );

        let bytes: Vec<u8> = call
            .try_into()
            .map_err(|_| RemoteWalletError::Protocol("Failed to encode QR call"))?;

        let encoded = probe_encode(&bytes, 400, QRHardwareCall::get_registry_type().get_type())
            .map_err(|_| RemoteWalletError::Protocol("Failed to encode UR"))?;

        Ok(encoded.data)
    }

    /// Generate UR-encoded sign request for transaction signing
    fn generate_sol_sign_request(
        &self,
        derivation_path: &DerivationPath,
        sign_data: &[u8],
    ) -> Result<String, RemoteWalletError> {
        let crypto_key_path = parse_crypto_key_path(derivation_path, self.mfp);
        let request_id = [0u8; 16].to_vec();
        let sol_sign_request = SolSignRequest::new(
            Some(request_id),
            sign_data.to_vec(),
            crypto_key_path,
            None,
            Some("solana cli".to_string()),
            SignType::Transaction,
        );

        let bytes: Vec<u8> = sol_sign_request
            .try_into()
            .map_err(|_| RemoteWalletError::Protocol("Failed to encode sign request"))?;

        let encoded = probe_encode(&bytes, 0xFFFFFFF, SolSignRequest::get_registry_type().get_type())
            .map_err(|_| RemoteWalletError::Protocol("Failed to encode UR"))?;

        Ok(encoded.data)
    }

    /// Parse public key from UR-encoded response
    fn parse_ur_pubkey(&self, ur: &str) -> Result<Vec<u8>, RemoteWalletError> {
        let result: ur_parse_lib::keystone_ur_decoder::URParseResult<CryptoMultiAccounts> =
            probe_decode(ur.to_lowercase())
                .map_err(|_| RemoteWalletError::Protocol("Failed to decode UR pubkey"))?;

        result
            .data
            .ok_or(RemoteWalletError::Protocol("No pubkey in response"))?
            .get_keys()
            .get(0)
            .ok_or(RemoteWalletError::Protocol("Empty pubkey list"))
            .map(|key| key.get_key())
    }

    /// Parse signature from UR-encoded response
    fn parse_ur_signature(&self, ur: &str) -> Result<Vec<u8>, RemoteWalletError> {
        let result: ur_parse_lib::keystone_ur_decoder::URParseResult<SolSignature> =
            probe_decode(ur.to_lowercase())
                .map_err(|_| RemoteWalletError::Protocol("Failed to decode UR signature"))?;

        Ok(result
            .data
            .ok_or(RemoteWalletError::Protocol("No signature in response"))?
            .get_signature()
            .as_slice()
            .to_vec())
    }

    /// Parse JSON field from response
    fn parse_json_field(&self, json_str: &str, field_name: &str) -> Result<String, RemoteWalletError> {
        let json = serde_json::from_str::<serde_json::Value>(json_str)
            .map_err(|_| RemoteWalletError::Protocol(ERROR_INVALID_JSON))?;

        json.get(field_name)
            .and_then(|v| v.as_str())
            .ok_or(RemoteWalletError::Protocol(ERROR_MISSING_FIELD))
            .map(String::from)
    }

    /// Low-level USB write to device
    fn device_write(&self, data: &[u8]) -> Result<(), RemoteWalletError> {
        const TIMEOUT_MS: std::time::Duration = std::time::Duration::from_secs(10);

        match self.transfer_type {
            rusb::TransferType::Interrupt => self
                .handle
                .write_interrupt(self.endpoint_out, data, TIMEOUT_MS)
                .map_err(|e| RemoteWalletError::Hid(format!("USB write failed: {e}")))?,
            rusb::TransferType::Bulk => self
                .handle
                .write_bulk(self.endpoint_out, data, TIMEOUT_MS)
                .map_err(|e| RemoteWalletError::Hid(format!("USB write failed: {e}")))?,
            _ => {
                return Err(RemoteWalletError::Protocol(
                    "Unsupported USB transfer type for write",
                ));
            }
        };

        Ok(())
    }

    /// Low-level USB read from device
    fn device_read(&self) -> Result<Vec<u8>, RemoteWalletError> {
        const TIMEOUT_MS: std::time::Duration = std::time::Duration::from_secs(10);
        let mut buf = vec![0u8; HID_PACKET_SIZE + HID_PREFIX_ZERO];

        let bytes_read = match self.transfer_type {
            rusb::TransferType::Interrupt => self
                .handle
                .read_interrupt(self.endpoint_in, &mut buf, TIMEOUT_MS)
                .map_err(|e| RemoteWalletError::Hid(format!("USB read failed: {e}")))?,
            rusb::TransferType::Bulk => self
                .handle
                .read_bulk(self.endpoint_in, &mut buf, TIMEOUT_MS)
                .map_err(|e| RemoteWalletError::Hid(format!("USB read failed: {e}")))?,
            _ => {
                return Err(RemoteWalletError::Protocol(
                    "Unsupported USB transfer type for read",
                ));
            }
        };

        buf.truncate(bytes_read);
        Ok(buf)
    }
}

impl RemoteWallet<rusb::Device<rusb::Context>> for KeystoneWallet {
    fn name(&self) -> &str {
        "Keystone hardware wallet"
    }

    fn read_device(
        &mut self,
        _dev_info: &rusb::Device<rusb::Context>,
    ) -> Result<RemoteWalletInfo, RemoteWalletError> {
        // Get device info (firmware version and MFP)
        println!("{}:{}", file!(), line!());
        let (version, mfp) = self.get_device_info()?;
        self.version = version;
        self.mfp = mfp;

        // Get device descriptor for model and serial
        let device_descriptor = self
            .device
            .device_descriptor()
            .map_err(|e| RemoteWalletError::Hid(format!("Failed to get device descriptor: {}", e)))?;

        let model = format!(
            "Keystone {:04x}:{:04x}",
            device_descriptor.vendor_id(),
            device_descriptor.product_id()
        );

        let serial = self.handle
            .read_serial_number_string_ascii(&device_descriptor)
            .unwrap_or_else(|_| "Unknown".to_string());

        // Try to get default pubkey
        let pubkey_result = self.get_pubkey(&DerivationPath::default(), false);
        let (pubkey, error) = match pubkey_result {
            Ok(pubkey) => (pubkey, None),
            Err(err) => (Pubkey::default(), Some(err)),
        };

        Ok(RemoteWalletInfo {
            model,
            manufacturer: Manufacturer::Keystone,
            serial,
            host_device_path: format!(
                "{:04x}:{:04x}",
                device_descriptor.vendor_id(),
                device_descriptor.product_id()
            ),
            pubkey,
            error,
        })
    }

    fn get_pubkey(
        &self,
        derivation_path: &DerivationPath,
        confirm_key: bool,
    ) -> Result<Pubkey, RemoteWalletError> {
        let ur_request = self.generate_hardware_call(derivation_path)?;

        if confirm_key {
            println!(
                "Waiting for your approval on {} {}",
                self.name(),
                self.pretty_path
            );
        }

        // TODO: Display QR code with ur_request here
        // For now, prompt user to scan
        println!("Please scan the QR code on your Keystone device");

        // Wait for response from device
        let json_response =
            self.send_apdu(CommandType::CmdResolveUR, ur_request.as_bytes())?;

        let pubkey_ur = self.parse_json_field(&json_response, JSON_FIELD_PUBKEY)?;
        let pubkey_bytes = self.parse_ur_pubkey(&pubkey_ur)?;

        if confirm_key {
            println!("{CHECK_MARK}Approved");
        }

        Pubkey::try_from(pubkey_bytes)
            .map_err(|_| RemoteWalletError::Protocol(ERROR_KEY_SIZE))
    }

    fn sign_message(
        &self,
        derivation_path: &DerivationPath,
        data: &[u8],
    ) -> Result<Signature, RemoteWalletError> {
        let ur_request = self.generate_sol_sign_request(derivation_path, data)?;

        println!(
            "Waiting for your approval on {} {}",
            self.name(),
            self.pretty_path
        );

        // TODO: Display QR code with ur_request here
        println!("Please scan the QR code on your Keystone device");

        // Wait for response from device
        let json_response =
            self.send_apdu(CommandType::CmdResolveUR, ur_request.as_bytes())?;

        let signature_ur = self.parse_json_field(&json_response, "signature")?;
        let signature_bytes = self.parse_ur_signature(&signature_ur)?;

        Signature::try_from(signature_bytes)
            .map_err(|_| RemoteWalletError::Protocol(ERROR_SIGNATURE_SIZE))
    }

    fn sign_offchain_message(
        &self,
        derivation_path: &DerivationPath,
        message: &[u8],
    ) -> Result<Signature, RemoteWalletError> {
        self.sign_message(derivation_path, message)
    }
}

/// Check if device is a Keystone
pub fn is_valid_keystone(vendor_id: u16, product_id: u16) -> bool {
    vendor_id == KEYSTONE_VID && product_id == KEYSTONE_PID
}

/// Parse derivation path into CryptoKeyPath for UR encoding
fn parse_crypto_key_path(
    derivation_path: &DerivationPath,
    mfp: Option<[u8; 4]>,
) -> CryptoKeyPath {
    let mut path_components = Vec::new();

    for index in derivation_path.path() {
        // PathComponent::new takes (index: Option<u32>, hardened: bool)
        // We'll use a reasonable approach assuming hardened components
        if let Ok(component) = PathComponent::new(Some(index.to_bits()), true) {
            path_components.push(component);
        }
    }

    // CryptoKeyPath::new takes (components, master_fingerprint, depth) and returns CryptoKeyPath.
    CryptoKeyPath::new(path_components, mfp, None)
}
