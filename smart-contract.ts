import {
  assert,
  MethodCallOptions,
  ContractTransaction,
  ByteString,
  hash256,
  method,
  prop,
  PubKey,
  Sig,
  SmartContract,
  Utils,
  UTXO,
  bsv,
  pubKey2Addr,
  FixedArray,
} from "scrypt-ts";

import Transaction = bsv.Transaction;
import Address = bsv.Address;
import Script = bsv.Script;

export type Staker = {
  addr: PubKey;
  stakedSatoshi: bigint;
  unlockTime: bigint;
};

export const N = 2;
export type Stakers = FixedArray<Staker, typeof N>;

export class StakingProtocol extends SmartContract {
  // The staker's info.
  @prop(true)
  staker: Staker;

  // The Shell's public key.
  @prop()
  readonly shell: PubKey;

  // The Staking Address public key.
  @prop()
  readonly target: PubKey;

  @prop(true)
  shellTokenReserve: bigint;

  constructor(shell: PubKey, target: PubKey, shellTokenReserve: bigint) {
    super(...arguments);
    this.shell = shell;
    this.target = target;
    this.shellTokenReserve = shellTokenReserve;
  }

  @method()
  public deposit(user: PubKey, fundIn: bigint, unlockTime: bigint) {
    assert(this.staker.stakedSatoshi == 0n, "staked");
    let outputs: ByteString = this.buildStateOutput(fundIn);
    outputs += this.buildChangeOutput();
    this.staker.stakedSatoshi += fundIn;
    this.staker.unlockTime = unlockTime;
    this.staker.addr = user;
    this.shellTokenReserve -= fundIn;
    assert(hash256(outputs) == this.ctx.hashOutputs, "hashOutputs mismatch");
  }

  public withdraw(fundOut: bigint) {
    assert(this.timeLock(this.staker.unlockTime), "unlockTime not yet reached");
    assert(this.staker.stakedSatoshi == fundOut, "not same amount");

    let outputs: ByteString = Utils.buildAddressOutput(
      pubKey2Addr(this.staker.addr),
      this.staker.stakedSatoshi
    );

    outputs += this.buildChangeOutput();
    this.shellTokenReserve += fundOut;
    assert(hash256(outputs) == this.ctx.hashOutputs, "hashOutputs mismatch");
  }
}

import { BSV20V2 } from "scrypt-ord";

import { RabinPubKey, RabinSig, RabinVerifier } from "scrypt-ts-lib";

export class Bsv20Loan extends BSV20V2 {
  @prop()
  lender: PubKey;

  @prop()
  borrower: PubKey;

  // Lent BSV-20 token amount.
  @prop()
  tokenAmt: bigint;

  // Fixed interest rate of the loan.
  // 1 = 1%
  @prop()
  interestRate: bigint;

  // Collateral satoshis.
  @prop()
  collateral: bigint;

  // Deadline of the loan.
  @prop()
  deadline: bigint;

  // Flag that indicates wether the
  // loan was already taken.
  @prop(true)
  taken: boolean;

  @prop()
  oraclePubKey: RabinPubKey;

  constructor(
    id: ByteString,
    sym: ByteString,
    max: bigint,
    dec: bigint,
    lender: PubKey,
    borrower: PubKey,
    tokenAmt: bigint,
    collateral: bigint,
    oraclePubKey: RabinPubKey
  ) {
    super(id, sym, max, dec);
    this.init(...arguments);

    this.lender = lender;
    this.borrower = borrower;
    this.tokenAmt = tokenAmt;
    this.collateral = collateral;
    this.taken = false;
    this.oraclePubKey = oraclePubKey;
  }

  @method()
  public borrow() {
    assert(!this.taken, "loan already taken");
    this.taken = true;

    let outputs = BSV20V2.buildTransferOutput(
      pubKey2Addr(this.borrower),
      this.id,
      this.tokenAmt
    );
    outputs += this.buildStateOutput(this.collateral);
    outputs += this.buildChangeOutput();
    assert(hash256(outputs) == this.ctx.hashOutputs, "hashOutputs mismatch");
  }

  @method()
  public repay(oracleMsg: ByteString, oracleSig: RabinSig) {
    assert(this.taken, "loan not taken yet");
    assert(
      RabinVerifier.verifySig(oracleMsg, oracleSig, this.oraclePubKey),
      "oracle sig verify failed"
    );
    assert(
      slice(this.prevouts, Constants.OutpointLen, Constants.OutpointLen * 2n) ==
        slice(oracleMsg, 0n, Constants.OutpointLen),
      "second input is not spending specified ordinal UTXO"
    );

    const utxoTokenAmt = byteString2Int(
      slice(oracleMsg, Constants.OutpointLen, 44n)
    );
    assert(utxoTokenAmt == this.tokenAmt, "invalid token amount");

    let outputs = BSV20V2.buildTransferOutput(
      pubKey2Addr(this.lender),
      this.id,
      this.tokenAmt
    );
    outputs += Utils.buildAddressOutput(
      pubKey2Addr(this.borrower),
      this.collateral
    );
    outputs += this.buildChangeOutput();

    // Enforce outputs.
    assert(hash256(outputs) == this.ctx.hashOutputs, "hashOutputs mismatch");
  }
}
