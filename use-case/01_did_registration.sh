#!/bin/sh

# This protocol describes, how a User U with U ∈ {RU, RO, I} registers a DID_U in VDR.
echo "Executing 01: DID registration"

pnpm hardhat register-did --accountName resourceOwner

accountNames=(accreditationBody resourceOwner resourceUser)

for accountName in "${accountNames[@]}"; do
    pnpm hardhat register-did --account-name "$accountName" --network localhost
done
