import {
  utils,
  Wallet,
  Provider,
  Contract,
  types,
  EIP712Signer,
} from "zksync-ethers";
import * as ethers from "ethers";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { Deployer } from "@matterlabs/hardhat-zksync-deploy";

// load env file
import dotenv from "dotenv";
import { serializeEip712 } from "zksync-ethers/build/utils";
import { bigint } from "hardhat/internal/core/params/argumentTypes";
dotenv.config();

// AA factory address: 0x43E657D98b8Bfd32B01E723D05E55DDB3247A404
// SC Account owner pk:  0xccdff81d1311ea16c96b3026a3fd355b72c11ef4b6f8904a2aacd6ae0ddb11b0
// SC Account deployed on address 0x10491562437a61De8B4DD9Af6891f44777214f2c
// Deadman Module address: 0x01A01C48079ECee96006D3C75756fa15c049E14F

const DEPLOYER_PRIVATE_KEY = process.env.WALLET_PRIVATE_KEY || "";

export default async function (hre: HardhatRuntimeEnvironment) {
  const provider = new Provider("https://sepolia.era.zksync.dev");
  const owner = new Wallet(DEPLOYER_PRIVATE_KEY).connect(provider);
  const accountArtifact = await hre.artifacts.readArtifact("AAwesomeAccount");
  const signer = new ethers.VoidSigner(
    "0x460e6f16116a4bD567Fc65E210b925C4299f21D5",
    provider
  );

  const account = new Contract(
    "0x0Bd203d8Ba716dcf12948e7352C0BEfE75d59668",
    accountArtifact.abi,
    owner
  );
  const encodedData = ethers.solidityPacked(
    ["address", "uint48"],
    ["0x460e6f16116a4bD567Fc65E210b925C4299f21D5", 12345]
  );

  //  installModule(uint256 moduleType, address module, bytes calldata initData)
  let installModuleTx = await account.installModule.populateTransaction(
    ethers.parseEther("0"),
    "0xfdF01289dec0293F1e9eb25BBF6a0c72987E1E90",
    encodedData,
    { from: "0x0Bd203d8Ba716dcf12948e7352C0BEfE75d59668", type: 113 }
  );
  installModuleTx = {
    ...installModuleTx,
    // from: "0x0Bd203d8Ba716dcf12948e7352C0BEfE75d59668",
    chainId: (await provider.getNetwork()).chainId,
    nonce: await provider.getTransactionCount(
      "0x0Bd203d8Ba716dcf12948e7352C0BEfE75d59668"
    ),

    customData: {
      gasPerPubdata: utils.DEFAULT_GAS_PER_PUBDATA_LIMIT,
    },
    value: ethers.parseEther("0"),
  };

  installModuleTx.gasPrice = await provider.getGasPrice();
  installModuleTx.gasLimit = await provider.estimateGas(installModuleTx);

  const signedTxHash = EIP712Signer.getSignedDigest(installModuleTx);

  const signature = ethers.concat([
    ethers.Signature.from(owner.signingKey.sign(signedTxHash)).serialized,
  ]);

  installModuleTx.customData = {
    ...installModuleTx.customData,
    customSignature: signature,
  };

  console.log("Installing module...");
  const sentTx = await provider.broadcastTransaction(
    types.Transaction.from(installModuleTx).serialized
  );

  await sentTx.wait();
}
