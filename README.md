# Privacy-Preserving On-chain Permissioning For KYC-Compliant Decentralized Applications

Decentralized applications (dApps) in Decentralized Finance (DeFi) face a fundamental tension between regulatory compliance requirements like KYC/AML and maintaining decentralization and privacy.
Existing permissioned DeFi solutions introduce centralized trust assumptions that undermine blockchain's decentralization.
This paper presents a novel synthesis of Self-Sovereign Identity (SSI), Zero-Knowledge Proofs (ZKPs), and Attribute-Based Access Control to enable privacy-preserving on-chain permissioning based on decentralized policy decisions.
We provide a comprehensive framework for permissioned dApps that aligns decentralized trust, privacy, and transparency harmonizing blockchain principles with regulatory compliance.
Our framework supports multiple proof types (equality, range, membership, and time-dependent) with efficient proof generation through a commit-and-prove scheme that moves credential authenticity verification outside the ZKP circuit.
Experimental evaluation of our KYC-compliant DeFi implementation shows considerable performance reduction for different proof types compared to baseline approaches.
We advances the state-of-the-art through a holistic approach, flexible proof mechanisms addressing diverse real-world requirements, and optimized proof generation enabling practical deployment.

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Node 20.16 or higher
- [Pipenv](https://pipenv.pypa.io/en/latest/)
- [pnpm](https://pnpm.io/installation)
- [ZoKrates](https://zokrates.github.io/gettingstarted.html#one-line-installation)

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-name>
   ```

2. Install Python dependencies:
   ```bash
   pipenv install
   pipenv install --dev
   ```

3. Install Node.js dependencies:
   ```bash
   pnpm install
   ```

## Running Experiments

To execute the experiments:

```bash
cd evaluate && ./run.sh
```

### Troubleshooting

On macOS with bash 3, you may encounter date calculation errors. Install GNU coreutils:
```bash
brew install coreutils
```