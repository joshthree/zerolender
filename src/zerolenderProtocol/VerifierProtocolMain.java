package zerolenderProtocol;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.ECPedersenCommitment;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class VerifierProtocolMain {
	public static void main(String[] args)
	{
		if(args.length != 7) {
			System.out.println("Usage:  java -cp ./bin;./jars/* zeroLender.VerifierProtocolMain baseFileName sizeOfUnit units numberOfRepayments bitsOfComparison(n) totalNumberOfInvestors numberOfFakeInvestors");
			System.exit(1);
		}
		boolean allGood = true;
		SecureRandom rand = new SecureRandom();
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		ECPoint h;
		ECCurve c = g.getCurve();
		BigInteger order = g.getCurve().getOrder();


		int sizeOfUnit = Integer.parseInt(args[1]); //105084
		int units = Integer.parseInt(args[2]); //1000
		int repayments = Integer.parseInt(args[3]); //36
		int n = Integer.parseInt(args[4]); // 10
		int min = sizeOfUnit/repayments - (1<<(n-1));
		int max = sizeOfUnit/repayments + (1<<(n-1)) - 1;
		int numInvestors = Integer.parseInt(args[5]);
		int numFakeInvestors = Integer.parseInt(args[6]);
		int numRealInvestors = numInvestors - numFakeInvestors;
		int[] totalRepaymentValues;
		ECPedersenCommitment[] totalRepaymentTable;
		ZKPProtocol schnorr = new ECSchnorrProver();
		BigInteger[] totalRepaymentKeys;
		CryptoData[][] table = null;
		String baseName = args[0];
		String transcriptFilename = baseName + ".part1.public";
		String borrowerPrivateFile = baseName + ".part1.borrower";
		String timerFile = baseName + ".part1.verifier.time";
		
		
		ObjectInputStream borrowerPrivateStream = null;
		ObjectInputStream transcriptStream = null;
		CryptoData miniEnv = null, revEnv = null;
		FileWriter timerStream = null;
		try {
			timerStream = new FileWriter(new File(timerFile));
			transcriptStream = new ObjectInputStream(new FileInputStream(new File(transcriptFilename)));
			borrowerPrivateStream = new ObjectInputStream(new FileInputStream(new File(borrowerPrivateFile)));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		long start = System.currentTimeMillis();
		//RepaymentPlan table = new RepaymentPlan(units, sizeOfUnit, min, max, totalRepaymentTable, totalRepaymentValues, totalRepaymentKeys, rand, miniEnv);
		try {
			ZKPProtocol[] unpackedRows = new ZKPProtocol[units];
			CryptoData[] rowPublicInputs = new CryptoData[units];
			ZKPProtocol[] unpackedCols = new ZKPProtocol[repayments];
			CryptoData[] colPublicInputs = new CryptoData[repayments];
			CryptoData hPacked = (CryptoData) transcriptStream.readObject();
			h = (hPacked).getECPointData(c);
			miniEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, g), hPacked});
			revEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, h), new ECPointData(g)});
			CryptoData[] rowEnv = new CryptoData[units];
			CryptoData[] colEnv = new CryptoData[repayments];

			//			borrowerPrivateStream.writeObject(totalRepaymentKeys);
			//			borrowerPrivateStream.writeObject(totalRepaymentValues);
			//			transcriptStream.writeObject(totalRepaymentTable);
			//			table.createRawTableProofs(rand, miniEnv, transcriptStream);
			totalRepaymentKeys = (BigInteger[]) borrowerPrivateStream.readObject();
			totalRepaymentValues = (int[]) borrowerPrivateStream.readObject();
			CryptoData[] tablePacked = ((CryptoData) transcriptStream.readObject()).getCryptoDataArray();
			table = new CryptoData[tablePacked.length][];
			for(int i = 0; i < tablePacked.length; i++) {
				table[i] = tablePacked[i].getCryptoDataArray();
			}
			totalRepaymentTable = (ECPedersenCommitment[]) transcriptStream.readObject();

			//			for(int i = 0; i < totalRepaymentValues.length; i++) {
			//				if(!totalRepaymentTable[i].verifyCommitment(BigInteger.valueOf(totalRepaymentValues[i]), totalRepaymentKeys[i], miniEnv)) System.out.println("Bad Commitments on total repayment table");;
			//			}

			CryptoData[] rowProof = (CryptoData[]) transcriptStream.readObject();
			CryptoData[] colProof = (CryptoData[]) transcriptStream.readObject();

			for(int i = 0; i < units; i++)
			{
				unpackedRows[i] = schnorr;
				ECPoint commProduct = c.getInfinity();
				for(int j = 0; j < repayments; j++)
				{
					commProduct = commProduct.add(table[i][j].getECPointData(c));
				}
				rowPublicInputs[i] = new CryptoDataArray(new CryptoData[] {new ECPointData(commProduct.subtract(g.multiply(BigInteger.valueOf(sizeOfUnit))))});
				rowEnv[i] = revEnv;
			}
			ZKPProtocol rowProver = new ZeroKnowledgeAndProver(unpackedRows);
			try {
				if(!rowProver.verifyFiatShamir(new CryptoDataArray(rowPublicInputs), rowProof[0], rowProof[1], new CryptoDataArray(rowEnv))) {
					System.out.println("Bad proof!!");
					allGood = false;
				}
			} catch (MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			for(int j = 0; j < repayments; j++)
			{
				unpackedCols[j] = schnorr;
				ECPoint commProduct = c.getInfinity();
				for(int i = 0; i < units; i++)
				{
					commProduct = commProduct.add(table[i][j].getECPointData(c));
				}
				colPublicInputs[j] = new CryptoDataArray(new CryptoData[] {new ECPointData(commProduct.subtract(totalRepaymentTable[j].getCommitment(miniEnv)))});
				colEnv[j] = revEnv;
			}
			ZKPProtocol colProver = new ZeroKnowledgeAndProver(unpackedCols);
			try {
				if(!colProver.verifyFiatShamir(new CryptoDataArray(colPublicInputs), colProof[0], colProof[1], new CryptoDataArray(colEnv))) {
					System.out.println("Bad proof!!");
					allGood = false;
				}
			} catch (MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			CryptoData[][][] rangeProofs = (CryptoData[][][]) transcriptStream.readObject();

			for(int i = 0; i < repayments; i++) {
				for(int j = 0; j < units; j++) {
					if(!ZKToolkit.rangeProofFiatShamirVerify(table[j][i], rangeProofs[j][i], BigInteger.valueOf(min),  BigInteger.valueOf(max), miniEnv))  {
						System.out.println("Bad range proof :-(");
						allGood = false;
					}
				}
			}

			transcriptStream.close();
			borrowerPrivateStream.close();
			//table.createRawTableProofs(rand, miniEnv, transcriptStream);
		} catch (IOException|ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		long end = System.currentTimeMillis();
		try {
			timerStream.write(end-start + " " + allGood);
			timerStream.close();
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
		allGood = true;
		transcriptFilename = baseName + ".part2.public";
		timerFile = baseName + ".part2.verifier.time";
		String[] investorString = new String[numInvestors];
		ObjectInputStream[] investorStream = new ObjectInputStream[numInvestors];
		try {

			timerStream = new FileWriter(new File(timerFile));
			transcriptStream = new ObjectInputStream(new FileInputStream(new File(transcriptFilename)));
			for(int i = 0; i < numInvestors; i++) {
				investorString[i] = baseName + ".part2.investor" + String.format("%03d", i);
				investorStream[i] = new ObjectInputStream(new FileInputStream(new File(investorString[i])));
			}
		} catch (IOException e) {
		}
		try {
			start = System.currentTimeMillis();
			CryptoData[][] mappingTableSerializable = (CryptoData[][]) transcriptStream.readObject();
			CryptoData[][] committedPermutation = new CryptoData[numInvestors][];
			int[][] permutation = new int[numInvestors][];
			BigInteger[][] permutationKeys = new BigInteger[numInvestors][];
			for(int i = 0; i < numInvestors; i++) {
				committedPermutation[i] = ((CryptoData) transcriptStream.readObject()).getCryptoDataArray();
			}
			for(int i = 0; i < numInvestors; i++) {
				permutation[i] = (int[]) transcriptStream.readObject();
				permutationKeys[i] = (BigInteger[]) transcriptStream.readObject();
				BigInteger packedPermutation = BigInteger.valueOf(permutation[i][numInvestors-1]);
				BigInteger numInvestorsBig = BigInteger.valueOf(units);
				for(int j = units-2; j >=0; j--)
				{
					packedPermutation.multiply(numInvestorsBig);
					packedPermutation.add(BigInteger.valueOf(permutation[i][j]));
				}
				for(int j = 0; j < numInvestors; j++) {
					if(!ZKToolkit.multiCommitment(packedPermutation, permutationKeys[i], miniEnv)[j].equals(committedPermutation[i][j].getECPointData(c))) {
						System.out.println("Bad Permutation Commitment!");
						allGood = false;
					}
				}
			}

			CryptoData[][] shuffledMappingTable = new CryptoData[units][];
			int[] temp1 = new int[units];
			int[] temp2;
			int[] totalPermutation = permutation[0];
			for(int i = 1; i < numInvestors; i++) {
				for(int j = 0; j < units; j++) {
					temp1[j] = totalPermutation[permutation[i][j]]; 
				}
				temp2 = totalPermutation;
				totalPermutation = temp1;
				temp1 = temp2;
			}
			for(int i = 0; i < units; i++) {
				shuffledMappingTable[i] = mappingTableSerializable[totalPermutation[i]];
			}

			CryptoData[] mTable = ((CryptoData) transcriptStream.readObject()).getCryptoDataArray();
			for(int i = 0; i < units; i++) {
				ECPoint totalComm = c.getInfinity();
				for(int j = 0; j < numInvestors; j++) {
					totalComm = totalComm.add(shuffledMappingTable[i][j].getECPointData(c));
				}
				CryptoData publicData = new CryptoDataArray(new ECPoint[] {totalComm.subtract(g)});
				CryptoData[] result = ((CryptoData[]) transcriptStream.readObject());
				try {
					if(!schnorr.verifyFiatShamir(publicData, result[0], result[1], revEnv)) {
						System.out.println("Bad Proof on Rows!");
						allGood = false;
					}
				} catch (MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			for(int j = 0; j < numInvestors; j++) {
				CryptoData[] result = ((CryptoData[]) transcriptStream.readObject());
				ECPoint totalComm = shuffledMappingTable[0][j].getECPointData(c);
				for(int i = 1; i < units; i++) {
					totalComm = totalComm.add(shuffledMappingTable[i][j].getECPointData(c));
				}
				CryptoData publicInputs = new CryptoDataArray(new CryptoData[] {new ECPointData(totalComm.subtract(mTable[j].getECPointData(c)))});
				try {
					if(!schnorr.verifyFiatShamir(publicInputs, result[0], result[1], revEnv)) {
						System.out.println("Bad Proof on Cols!");
						allGood = false;
					}
				} catch (MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

			CryptoData[] largeEnvInner = new CryptoData[repayments+1];
			ZKPProtocol[] largeProofAndUnpacked = new ZKPProtocol[repayments+1];

			for(int j = 0; j < repayments+1; j++) {
				largeEnvInner[j] = revEnv;
				largeProofAndUnpacked[j] = schnorr;
			}

			ZKPProtocol largeProofAnd = new ZeroKnowledgeAndProver(largeProofAndUnpacked);
			ZKPProtocol largeProof = new ZeroKnowledgeOrProver(new ZKPProtocol[] {largeProofAnd,largeProofAnd});

			CryptoData largeEnvInnerPacked = new CryptoDataArray(largeEnvInner);
			CryptoData largeEnv = new CryptoDataArray(new CryptoData[] {largeEnvInnerPacked, largeEnvInnerPacked});
			CryptoData[][][] vHat = new CryptoData[numInvestors][repayments][units];
			for(int k = 0; k < numInvestors; k++) {
				for(int i = 0; i < units; i++){
					CryptoData[] innerPublicData0 = new CryptoData[repayments+1];
					CryptoData[] innerPublicData1 = new CryptoData[repayments+1];
					CryptoData[] middlePublicData = new CryptoData[2];
					for(int j = 0; j < repayments; j++) {
						vHat[k][j][i] = (CryptoData) transcriptStream.readObject();
						innerPublicData0[j] = new CryptoDataArray(new CryptoData[] {vHat[k][j][i]});
						innerPublicData1[j] = new CryptoDataArray(new CryptoData[] {new ECPointData(vHat[k][j][i].getECPointData(c).subtract(table[i][j].getECPointData(c)))});
					}
					innerPublicData0[repayments] = new CryptoDataArray(new CryptoData[] {shuffledMappingTable[i][k]});
					innerPublicData1[repayments] = new CryptoDataArray(new CryptoData[] {new ECPointData(shuffledMappingTable[i][k].getECPointData(c).subtract(g))});
					middlePublicData[0] =  new CryptoDataArray(innerPublicData0);
					middlePublicData[1] =  new CryptoDataArray(innerPublicData1);
					
					CryptoData[] transcript = (CryptoData[]) transcriptStream.readObject();
					
					try {
						if(!largeProof.verifyFiatShamir(new CryptoDataArray(middlePublicData), transcript[0], transcript[1], largeEnv)) {
							System.out.println("Bad Proof on large proof");
							allGood = false;
						}
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
							| ArraySizesDoNotMatchException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
			}

			transcriptStream.close();
			end = System.currentTimeMillis();
			try {
				System.out.println(end-start + " " + allGood);
				timerStream.write(end-start + " " + allGood);
				timerStream.close();
			} catch (IOException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
			
		} catch (ClassNotFoundException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
