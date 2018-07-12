using NBitcoin;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using NBitcoin.RPC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace NBitcoin.Altcoins
{
	// Reference: https://github.com/dashpay/dash/blob/master/src/chainparams.cpp
	public class Digitalcoin : NetworkSetBase
	{
		public static Digitalcoin Instance { get; } = new Digitalcoin();

		public override string CryptoCode => "DGC";

		private Digitalcoin()
		{

		}

		public class DGCConsensusFactory : ConsensusFactory
		{
			private DGCConsensusFactory()
			{
			}

			public static DGCConsensusFactory Instance { get; } = new DGCConsensusFactory();

			public override BlockHeader CreateBlockHeader()
			{
				return new DGCBlockHeader();
			}
			public override Block CreateBlock()
			{
				return new DGCBlock(new DGCBlockHeader());
			}
		}

#pragma warning disable CS0618 // Type or member is obsolete
		public class DGCBlockHeader : BlockHeader
		{
			public override uint256 GetPoWHash()
			{
				var headerBytes = this.ToBytes();
				var h = NBitcoin.Crypto.SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32);
				return new uint256(h);
			}
		}

		public class DGCBlock : Block
		{
#pragma warning disable CS0612 // Type or member is obsolete
			public DGCBlock(DGCBlockHeader h) : base(h)
#pragma warning restore CS0612 // Type or member is obsolete
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return Digitalcoin.Instance.Mainnet.Consensus.ConsensusFactory;
			}
		}
#pragma warning restore CS0618 // Type or member is obsolete

		protected override void PostInit()
		{
			RegisterDefaultCookiePath(Mainnet, ".cookie");
			RegisterDefaultCookiePath(Regtest, "regtest", ".cookie");
			RegisterDefaultCookiePath(Testnet, "testnet3", ".cookie");
		}

		//static uint256 GetPoWHash(BlockHeader header)
		//{
		//	var headerBytes = header.ToBytes();
		//	var h = NBitcoin.Crypto.SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32);
		//	return new uint256(h);
		//}

		protected override NetworkBuilder CreateMainnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 4730400,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256("0x000007d91d1254d60e2dd1ae580383070a4ddffa4c64c2eeb4a2f9ecc0414343"),
				PowLimit = new Target(new uint256("0x0000100000000000000000000000000000000000000000000000000000000000")),
				MinimumChainWork = new uint256("0x0000100000000000000000000000000000000000000001117564a5d286356cb6"),
				PowTargetTimespan = TimeSpan.FromSeconds(108 * 40),
				PowTargetSpacing = TimeSpan.FromSeconds(40),
				PowAllowMinDifficultyBlocks = false,
				CoinbaseMaturity = 5,
				PowNoRetargeting = false,
				//RuleChangeActivationThreshold = 1916,
				//MinerConfirmationWindow = 2016,
				ConsensusFactory = DGCConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 30 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 5 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 128 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("dgc"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("dgc"))
			   .SetMagic(0xDBB6C0FB)
			.SetPort(7999)
			.SetRPCPort(7998)
			.SetMaxP2PVersion(70208)
			.SetName("digitalcoin-main")
			.AddAlias("digitalcoin-mainnet")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("brekki_1", "82.165.30.169"),
				new DNSSeedData("brekki_2", "212.227.204.145"),
			})
			.AddSeeds(new NetworkAddress[0])
			   .SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000001152abc11024b7593cf60c90ec6a4c50770732720c3524136f2f9ff95c5b2ecf8ff8751f0ff0f1eb0410a000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3104ffff001d0104294469676974616c636f696e2c20412043757272656e637920666f722061204469676974616c20416765ffffffff0100f2052a01000000434104a5814813115273a109cff99907ba4a05d951873dae7acb6c973d0c9e7c88911a3dbc9aa600deac241b91707e7b4ffb30ad91c8e56e695a1ddf318592988afe0aac00000000");

			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 4730400,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256("0x000007d91d1254d60e2dd1ae580383070a4ddffa4c64c2eeb4a2f9ecc0414343"),
				PowLimit = new Target(new uint256("0x0000100000000000000000000000000000000000000000000000000000000000")),
				MinimumChainWork = new uint256("0x0000100000000000000000000000000000000000000001117564a5d286356cb6"),
				PowTargetTimespan = TimeSpan.FromSeconds(108 * 40),
				PowTargetSpacing = TimeSpan.FromSeconds(40),
				PowAllowMinDifficultyBlocks = false,
				CoinbaseMaturity = 6,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				ConsensusFactory = DGCConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 30 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 5 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 128 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("dgc"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("dgc"))
			.SetMagic(0xAB6B0CBF)
			.SetPort(7999)
			.SetRPCPort(7998)
			.SetMaxP2PVersion(70208)
			.SetName("digitalcoin-test")
			.AddAlias("digitalcoin-testnet")
			.AddSeeds(new NetworkAddress[0])
				   .SetGenesis("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0487f399510105062f503253482fffffffff0100c2eb0b000000002321036c1bee7e18f83cde7802c42cff98e757b97cf8826f2d7b102d371374a1ec3162ac00000000");


			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 4730400,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256("0x000007d91d1254d60e2dd1ae580383070a4ddffa4c64c2eeb4a2f9ecc0414343"),
				PowLimit = new Target(new uint256("0x0000100000000000000000000000000000000000000000000000000000000000")),
				MinimumChainWork = new uint256("0x0000100000000000000000000000000000000000000001117564a5d286356cb6"),
				PowTargetTimespan = TimeSpan.FromSeconds(108 * 40),
				PowTargetSpacing = TimeSpan.FromSeconds(40),
				PowAllowMinDifficultyBlocks = false,
				CoinbaseMaturity = 6,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				ConsensusFactory = DGCConsensusFactory.Instance,
				SupportSegwit = false
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 30 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 5 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 128 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("dgc"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("dgc"))
			.SetMagic(0xAC6B0CBF)
			.SetPort(7999)
			.SetRPCPort(7998)
			.SetMaxP2PVersion(70208)
			.SetName("digitalcoin-reg")
			   .AddAlias("digitalcoin-regtest")
			.AddSeeds(new NetworkAddress[0])
				   .SetGenesis("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0487f399510105062f503253482fffffffff0100c2eb0b000000002321036c1bee7e18f83cde7802c42cff98e757b97cf8826f2d7b102d371374a1ec3162ac00000000");


			return builder;
		}
	}
}