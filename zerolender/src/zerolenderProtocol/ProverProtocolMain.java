package zerolenderProtocol;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

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
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class ProverProtocolMain {
	public static void main(String[] args)
	{
		if(args.length != 7) {
			System.out.println("Usage:  java -cp ./bin;./jars/* zeroLender.ProverProtocolMain baseFileName sizeOfUnit numberOfUnits numberOfRepayments bitsOfComparison(n) totalNumberOfInvestors numberOfFakeInvestors");
			System.exit(1);
		}
		SecureRandom rand = new SecureRandom();
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		ECCurve curve = g.getCurve();
		BigInteger order = g.getCurve().getOrder();
		BigInteger random;
		do {
			random = new BigInteger(order.bitLength(), rand);
		}while(random.compareTo(order) >= 0);
		ECPoint h = g.multiply(random);

		CryptoData miniEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g), new ECPointData(h)});

		System.out.println("Creating raw repayment table:  ");
		int sizeOfUnit = Integer.parseInt(args[1]); //105084
		int numberOfUnits = Integer.parseInt(args[2]); //1000
		int numberOfRepayments = Integer.parseInt(args[3]); //36
		int n = Integer.parseInt(args[4]); // 10
		int min = sizeOfUnit/numberOfRepayments - (1<<(n-1));
		int max = sizeOfUnit/numberOfRepayments + (1<<(n-1)) - 1;
		int numInvestors = Integer.parseInt(args[5]);
		int numFakeInvestors = Integer.parseInt(args[6]);
		int numRealInvestors = numInvestors - numFakeInvestors;
		int[] totalRepaymentValues = new int[numberOfRepayments];
		ECPedersenCommitment[] totalRepaymentTable = new ECPedersenCommitment[numberOfRepayments];
		BigInteger[] totalRepaymentKeys = new BigInteger[numberOfRepayments];
		String baseName = args[0];
		String transcriptFilename = baseName + ".part1.public";
		String borrowerPrivateFile = baseName + ".part1.borrower";
		ObjectOutputStream borrowerPrivateStream = null;
		ObjectOutputStream transcriptStream = null;
		try {
			transcriptStream = new ObjectOutputStream(new FileOutputStream(new File(transcriptFilename)));
			borrowerPrivateStream = new ObjectOutputStream(new FileOutputStream(new File(borrowerPrivateFile)));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		for(int i = 0; i < numberOfRepayments; i++)
		{
			totalRepaymentValues[i] = numberOfUnits * sizeOfUnit / numberOfRepayments;
			do {
				random = new BigInteger(order.bitLength(), rand);
			}while(random.compareTo(order) >= 0);
			totalRepaymentKeys[i] = random;
			totalRepaymentTable[i] = new ECPedersenCommitment(BigInteger.valueOf(totalRepaymentValues[i]), totalRepaymentKeys[i], miniEnv);
		}

		RepaymentPlan table = new RepaymentPlan(numberOfUnits, sizeOfUnit, min, max, totalRepaymentTable, totalRepaymentValues, totalRepaymentKeys, rand, miniEnv);
		try {
			borrowerPrivateStream.writeObject(totalRepaymentKeys);
			borrowerPrivateStream.writeObject(totalRepaymentValues);
			transcriptStream.writeObject(totalRepaymentTable);
			table.createRawTableProofs(rand, miniEnv, transcriptStream);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			transcriptStream.flush();
			borrowerPrivateStream.flush();
			transcriptStream.close();
			borrowerPrivateStream.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//Part 1 done
		//Beginning part 2

		transcriptFilename = baseName + ".part2.public";
		String[] investorString = new String[numInvestors];
		ObjectOutputStream[] investorStream = new ObjectOutputStream[numInvestors];
		try {
			transcriptStream = new ObjectOutputStream(new FileOutputStream(new File(transcriptFilename)));
			for(int i = 0; i < numInvestors; i++) {
				investorString[i] = baseName + ".part2.investor" + String.format("%03d", i);
				investorStream[i] = new ObjectOutputStream(new FileOutputStream(new File(investorString[i])));
			}
		} catch (IOException e) {
		}
		boolean[][] mappingTableValues = new boolean[numberOfUnits][numInvestors];
		BigInteger[][] mappingTableKeys = new BigInteger[numberOfUnits][numInvestors];
		ECPoint[][] mappingTable = new ECPoint[numberOfUnits][numInvestors];
		CryptoData[][] mappingTableSerializable = new CryptoData[numberOfUnits][numInvestors];

		int[] mValues = new int[numInvestors];
		float[] mProportion = new float[numRealInvestors];
		BigInteger[] mKeys = new BigInteger[numInvestors];
		ECPoint[] mTable = new ECPoint[numInvestors];

		float total = 0;

		for(int i = 0; i < numRealInvestors; i++) {
			total += mProportion[i] = rand.nextFloat();
		}

		int totalM = 0;
		for(int i = 0; i < numRealInvestors; i++) {
			totalM += mValues[i] = (int) ((mProportion[i]/total) * numberOfUnits);
		}
		if(totalM < numberOfUnits)
		{
			int i = 0;
			while(totalM != numberOfUnits){
				mValues[i]++;
				i = (i + 1) % numRealInvestors;
				totalM++;
			}
		}
		if(totalM > numberOfUnits)
		{
			int i = 0;
			while(totalM != numberOfUnits){
				while(mValues[i] <= 1) {
					i = (i + 1) % numRealInvestors;
				}
				mValues[i]--;
				i = (i + 1) % numRealInvestors;
				totalM--;
			}
		}
		for(int i = 0; i < numInvestors; i++)
		{
			mKeys[i] = ZKToolkit.random(order, rand);
			mTable[i] = g.multiply(BigInteger.valueOf(mValues[i])).add(h.multiply(mKeys[i]));
		}
		{
//			int k = 0;
//			for(int i = 0; i < mValues.length; i++) {
//				for(int j = 0; j < mValues[i]; j++) {
//					mappingTableValues[i][k] = true;
//					k++;
//				}
//			}
			int count1 = 0;
			int count2 = 0;
			for(int i = 0; i < numberOfUnits; i++) {
				while(count1 == mValues[count2]) {
					count1 = 0;
					count2++;
				}
				mappingTableValues[i][count2] = true;
				count1++;
			}
			for(int i = 0; i < numberOfUnits; i++) {
				for(int j = 0; j < numInvestors; j++) {
					mappingTableKeys[i][j] = ZKToolkit.random(order, rand);
					if(mappingTableValues[i][j])
						mappingTable[i][j] = g.add(h.multiply(mappingTableKeys[i][j]));
					else
						mappingTable[i][j] = h.multiply(mappingTableKeys[i][j]);
					mappingTableSerializable[i][j] = new ECPointData(mappingTable[i][j]);
				}
			}
		}
		int mTotal=0;
		for(int i = 0; i < mValues.length; i++)
		{
			System.out.println("\t"+mValues[i]);
			mTotal += mValues[i];
		}
		System.out.println("\t\t" + mTotal);
		for(int i = 0; i < mappingTableValues.length; i++)
		{
			for(int j = 0; j < mappingTableValues[i].length; j++) {
				
				if(mappingTableValues[i][j]) System.out.print(1 + ", ");
				else System.out.print(0 + ", ");
			}
			System.out.println();
		}
		try {
			transcriptStream.writeObject(mappingTableSerializable);
			transcriptStream.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		ECPoint[][] committedPermutation = new ECPoint[numInvestors][];
		ECPoint[][] committedPermutation2 = new ECPoint[numInvestors][];
		BigInteger[][] permutationKeys = new BigInteger[numInvestors][numberOfUnits];
		int[][] permutations = new int[numInvestors][numberOfUnits];

		for(int i = 0; i < numInvestors; i++)
		{
			for(int j = 0; j < numberOfUnits; j++) {
				permutationKeys[i][j] = ZKToolkit.random(order, rand);
				permutations[i][j] = j;
			}
			for(int j = numberOfUnits-1; j > 0; j--)
			{		
				int num = rand.nextInt(j+1);
				int temp = permutations[i][j];
				permutations[i][j] = permutations[i][num];
				permutations[i][num] = temp;
			}
			BigInteger packedPermutation = BigInteger.valueOf(permutations[i][numInvestors-1]);
			BigInteger numInvestorsBig = BigInteger.valueOf(numInvestors);
			for(int j = numberOfUnits-2; j >=0; j--)
			{
				packedPermutation.multiply(numInvestorsBig);
				packedPermutation.add(BigInteger.valueOf(permutations[i][j]));
			}
			committedPermutation[i] = ZKToolkit.multiCommitment(packedPermutation, permutationKeys[i], miniEnv);
			
		}
		for(int i = 0; i < numInvestors; i++) {
			try {
				transcriptStream.writeObject(new CryptoDataArray(committedPermutation[i]));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		for(int i = 0; i < numInvestors; i++) {
			try {
				transcriptStream.writeObject(permutations[i]);
				transcriptStream.writeObject(permutationKeys[i]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		for(int i = 0; i < numInvestors; i++)
		{
			BigInteger packedPermutation = BigInteger.valueOf(permutations[i][numInvestors-1]);
			BigInteger numInvestorsBig = BigInteger.valueOf(numberOfUnits);
			for(int j = numberOfUnits-2; j >=0; j--)
			{
				packedPermutation.multiply(numInvestorsBig);
				packedPermutation.add(BigInteger.valueOf(permutations[i][j]));
			}
			committedPermutation2[i] = ZKToolkit.multiCommitment(packedPermutation, permutationKeys[i], miniEnv);
			for(int j = 0; j < numInvestors; j++) {
				if(!committedPermutation2[i][j].equals(committedPermutation[i][j]))System.out.println("Bad Permutation Commitment!");
			}
		}
		ECPoint[][] shuffledMappingTable = new ECPoint[numberOfUnits][];
		boolean[][] shuffledMappingTableValues = new boolean[numberOfUnits][];
		BigInteger[][] shuffledMappingTableKeys = new BigInteger[numberOfUnits][];
		int[] temp1 = new int[numberOfUnits];
		int[] temp2;
		int[] totalPermutation = permutations[0];
		for(int i = 1; i < numInvestors; i++) {
			System.out.println("applying new:");
			for(int j = 0; j < numberOfUnits; j++) {
				temp1[j] = totalPermutation[permutations[i][j]]; 
				System.out.printf("%d --> %d\n", permutations[i][j], j);
			}
			System.out.println();
			temp2 = totalPermutation;
			totalPermutation = temp1;
			temp1 = temp2;
			System.out.println("Total now:");
			for(int j = 0; j < totalPermutation.length; j++)
			{
				System.out.printf("%d --> %d\n", totalPermutation[j], j);
			}
			System.out.println();
		}
		for(int i = 0; i < numberOfUnits; i++) {
			shuffledMappingTable[i] = mappingTable[totalPermutation[i]];
			shuffledMappingTableValues[i] = mappingTableValues[totalPermutation[i]];
			shuffledMappingTableKeys[i] = mappingTableKeys[totalPermutation[i]];
		}
		for(int i = 0; i < numInvestors; i++) {
			try {
				investorStream[i].writeObject(shuffledMappingTableValues[i]);
				investorStream[i].writeObject(shuffledMappingTableKeys[i]);
				investorStream[i].writeObject(table.uncommittedTable[i]);
				investorStream[i].writeObject(table.keys[i]);
				investorStream[i].writeObject(mValues[i]);
				investorStream[i].writeObject(mKeys[i]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		for(int i = 0; i < numInvestors; i++)
		{
			try {
				investorStream[i].flush();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		for(int i = 0; i < mappingTableValues.length; i++)
		{
			for(int j = 0; j < mappingTableValues[i].length; j++) {
				
				if(shuffledMappingTableValues[i][j]) System.out.print(1 + ", ");
				else System.out.print(0 + ", ");
			}
			System.out.println();
		}
		table.consolidateTable(numInvestors, shuffledMappingTableValues, shuffledMappingTableKeys, shuffledMappingTable, mValues, mKeys, mTable, rand, transcriptStream, miniEnv);
	}
}
