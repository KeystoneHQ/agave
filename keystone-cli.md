# Keystone CLI 命令测试集合

## 0) 基础检查
```bash
cargo run -p solana-cli -- --version
cargo run -p solana-keygen -- --version
```

## 1) 网络与默认钱包

### 主网
```bash
cargo run -p solana-cli -- config set --url https://api.mainnet-beta.solana.com
cargo run -p solana-cli -- config set --keypair "usb://keystone?key=0"
cargo run -p solana-cli -- config get
```

### Devnet（测试推荐）
```bash
cargo run -p solana-cli -- config set --url https://api.devnet.solana.com
cargo run -p solana-cli -- config set --keypair "usb://keystone?key=0"
cargo run -p solana-cli -- config get
```

## 2) 地址与余额
```bash
# 从 Keystone 取地址（pubkey）
cargo run -p solana-keygen -- pubkey "usb://keystone?key=0"

# 查默认 signer 余额
cargo run -p solana-cli -- balance

# 查指定地址余额（示例）
cargo run -p solana-cli -- balance FUL6WteTuK81eHaQrMnLPqMRJvtUs5qX4Tt7unLRyJrG
```

## 3) Devnet 充币（仅 Devnet）
```bash
cargo run -p solana-cli -- airdrop 1
cargo run -p solana-cli -- balance
```

## 4) 转账测试

### 转给已存在地址
```bash
cargo run -p solana-cli -- transfer <TO_ADDRESS> 0.0001
```

### 转给未激活地址（首次收款）
```bash
cargo run -p solana-cli -- transfer <TO_ADDRESS> 0.001 --allow-unfunded-recipient
```

### 指定 lamports（避免小数）
```bash
cargo run -p solana-cli -- transfer <TO_ADDRESS> 100000 --lamports --allow-unfunded-recipient
```

## 5) 交易确认与详情
```bash
# 转账命令返回签名后，替换 <SIG>
cargo run -p solana-cli -- confirm <SIG>
cargo run -p solana-cli -- transaction <SIG>
```

## 6) 常用错误快速处理

### `recipient is not funded`
```bash
cargo run -p solana-cli -- transfer <TO_ADDRESS> 0.001 --allow-unfunded-recipient
```

### `insufficient funds for rent`
```bash
cargo run -p solana-cli -- rent 0
# 首次转账金额需 >= rent 结果
```

### 查看当前配置
```bash
cargo run -p solana-cli -- config get
```

## 7) 端到端最小回归（建议每次改 keystone.rs 后跑）
```bash
cargo run -p solana-cli -- config get
cargo run -p solana-keygen -- pubkey "usb://keystone?key=0"
cargo run -p solana-cli -- balance
cargo run -p solana-cli -- transfer <TO_ADDRESS> 100000 --lamports --allow-unfunded-recipient
# 复制上一条输出的签名到下面
cargo run -p solana-cli -- confirm <SIG>
```

## 8) 其他交易类型（非 transfer）

### 8.1 Nonce 账户交易
```bash
# 创建 nonce 账户（建议先在 devnet 测）
cargo run -p solana-keygen -- new -o nonce-account.json --no-bip39-passphrase
cargo run -p solana-cli -- create-nonce-account nonce-account.json 0.01

# 查看 nonce
cargo run -p solana-cli -- nonce $(cargo run -p solana-keygen -- pubkey nonce-account.json)

# 刷新 nonce
cargo run -p solana-cli -- new-nonce $(cargo run -p solana-keygen -- pubkey nonce-account.json)
```

### 8.2 Stake 账户交易
```bash
# 创建 stake 账户
cargo run -p solana-keygen -- new -o stake-account.json --no-bip39-passphrase
cargo run -p solana-cli -- create-stake-account stake-account.json 0.1

# 查看 stake 账户
cargo run -p solana-cli -- stake-account $(cargo run -p solana-keygen -- pubkey stake-account.json)

# 委托质押（<VOTE_ACCOUNT> 替换成目标验证者 vote account）
cargo run -p solana-cli -- delegate-stake $(cargo run -p solana-keygen -- pubkey stake-account.json) <VOTE_ACCOUNT>

# 取消委托
cargo run -p solana-cli -- deactivate-stake $(cargo run -p solana-keygen -- pubkey stake-account.json)

# 提现（仅在可提现状态下）
cargo run -p solana-cli -- withdraw-stake $(cargo run -p solana-keygen -- pubkey stake-account.json) <TO_ADDRESS> 0.01
```

### 8.3 Vote 账户交易（验证者场景）
```bash
# 查看 vote 账户
cargo run -p solana-cli -- vote-account <VOTE_ACCOUNT>

# 从 vote 账户提取（有权限时）
cargo run -p solana-cli -- withdraw-from-vote-account <VOTE_ACCOUNT> <TO_ADDRESS> 0.01
```

### 8.4 Program 相关交易
```bash
# Program 子命令入口（部署/关闭等）
cargo run -p solana-cli -- program --help
```
