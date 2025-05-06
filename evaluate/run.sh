#!/bin/bash

set -e

export WORKDIR=$(cd "$(dirname $(dirname $0))" && pwd)
export PATH=$PATH:/Users/$USER/.zokrates/bin

RESULTFILE="$WORKDIR/evaluate/result.csv"
PDPBASEPATH="contracts/src/pdp"
PDPBASEDIR="$WORKDIR/$PDPBASEPATH"

WITNESSPARAMSFILE="witness-parameters.txt"
WITNESSFILE="witness"
OUTFILE=out
SCRIPTFILE="attestation.py"
PKFILE="proving.key"
VKFILE="verification.key"
VERIFIERFILE="Verifier.sol"

if [ ! -f "$RESULTFILE" ]
then
	echo "condition type,amount,timestamp,gas (wei),witness_time (s),setup_time (s),prove_time (s),compiled_size (MB),proving_key_size (kB),verification_key_size (kB)" > $RESULTFILE
fi

declare -a patterns=("treecred_equality" "treecred_range" "treecred_membership")
declare -a amounts=(1 2 4 8 16)

for PATTERN in "${patterns[@]}"
do
  echo "### START pattern: $PATTERN ###"
  DIR="$WORKDIR/src/patterns/$PATTERN"
  INDIR="$DIR/in"

  for AMOUNT in "${amounts[@]}"
  do
    OUTDIR="$DIR/out/$AMOUNT"
    ZOKFILE="$AMOUNT.zok"
    PDPDIR="$PDPBASEDIR/$PATTERN/$AMOUNT"
    PDPPATH="$PDPBASEPATH/$PATTERN/$AMOUNT"
    PDPCONTRACT="$AMOUNT$PATTERN"Verifier

    mkdir -p "$OUTDIR"

    # Attestation
    python "$DIR/$SCRIPTFILE" -a "$AMOUNT" > "$OUTDIR/$WITNESSPARAMSFILE"

    # Witness
    zokrates compile -i "$INDIR/$ZOKFILE" -o "$OUTDIR/$OUTFILE" -r "$OUTDIR/$OUTFILE.r1cs"
    compiledSize=$(du -m "$OUTDIR/$OUTFILE" | cut -f1)

    start=$(gdate +%s%3N)
    cat "$OUTDIR/$WITNESSPARAMSFILE" | xargs zokrates compute-witness -i "$OUTDIR/$OUTFILE" -o "$OUTDIR/$WITNESSFILE" --circom-witness "$OUTDIR/$OUTFILE.wtns" -a
    end=$(gdate +%s%3N)
    witnessDur=$(echo "scale=2;($end-$start)/1000" | bc)
    mv "abi.json" "$OUTDIR"
    # Setup
    start=$(gdate +%s%3N)
    zokrates setup -i "$OUTDIR/$OUTFILE" -p "$OUTDIR/$PKFILE" -v "$OUTDIR/$VKFILE"
    end=$(gdate +%s%3N)
    setupDur=$(echo "scale=2;($end-$start)/1000" | bc)

    provingKeySize=$(du -k "$OUTDIR/$PKFILE"  | cut -f1)
    verificationKeySize=$(du -k "$OUTDIR/$VKFILE" | cut -f1)

    # Verification
    zokrates export-verifier -i "$OUTDIR/$VKFILE" -o "$OUTDIR/$VERIFIERFILE"
    mkdir -p "$PDPDIR"
    cp "$OUTDIR/$VERIFIERFILE" "$PDPDIR/$VERIFIERFILE"
    sed 's/public view returns (bool r)/public returns (bool r)/g' "$OUTDIR/$VERIFIERFILE" > "$PDPDIR/$VERIFIERFILE"
    pnpm hardhat deploy-pdp --source-path "$PDPPATH/$VERIFIERFILE" --target-name "$PDPCONTRACT" --network localhost

    # Proving
    start=$(gdate +%s%3N)
    zokrates generate-proof -i "$OUTDIR/$OUTFILE" -j "$OUTDIR/proof.json" -p "$OUTDIR/$PKFILE" -w "$OUTDIR/$WITNESSFILE"
    end=$(gdate +%s%3N)
    proofDur=$(echo "scale=2;($end-$start)/1000" | bc)

    txCost=$(pnpm hardhat test-pdp --target-name "$PDPCONTRACT" --proof "$(cat "$OUTDIR/proof.json")" --network localhost)

    ROW="$PATTERN,$AMOUNT,$(gdate +%s),$txCost,$witnessDur,$setupDur,$proofDur,$compiledSize,$provingKeySize,$verificationKeySize"
    echo $ROW >> $RESULTFILE

    echo $ROW
  done

  echo "### END pattern: $PATTERN ###"
  echo ""
done