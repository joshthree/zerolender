package zerolenderProtocol;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.InputMismatchException;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

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

public class RepaymentPlan {
	public ECPoint[][] table;
	public int[][] uncommittedTable;
	public BigInteger[][] keys;
	public ECPoint[][] consolidatedTable;
	public BigInteger[][] consolidatedTableKeys;
	public int[][] consolidatedTableValues;
	private int min;
	private int max;
	private ECPedersenCommitment[] totalRepaymentTable;
	private int[] totalRepaymentValues;
	private BigInteger[] totalRepaymentKeys;
	private int units;
	private int sizeOfRepayment;
	private int repayments;
	private int numInvestors;
	
	private int numRepayment;

	private byte[][] mappingTableValues;
	private BigInteger[][] mappingTableKey;
	private CryptoData[][] mappingTable;
	
	
	public RepaymentPlan(int units, int sizeOfRepayment, int min, int max,ECPedersenCommitment[] totalRepaymentTable, int[] totalRepaymentValues, BigInteger[] totalRepaymentKeys,SecureRandom rand, CryptoData commitmentEnvironment) {
		if(units <= 0 || sizeOfRepayment <= 0 || min <= 0 || max <= 0) throw new InputMismatchException("Expected positive numbers");
		
		this.units = units;
		this.sizeOfRepayment = sizeOfRepayment;
		this.min = min;
		this.max = max;
		this.totalRepaymentKeys = totalRepaymentKeys.clone();
		this.totalRepaymentTable = totalRepaymentTable.clone();
		this.totalRepaymentValues = totalRepaymentValues;
		
		if(min >= max) throw new InputMismatchException("min should be less than max.");
		this.repayments = totalRepaymentValues.length;
		CryptoData[] e = commitmentEnvironment.getCryptoDataArray();
		ECCurve c = e[0].getECCurveData();
		ECPoint g = e[0].getECPointData(c);
		ECPoint h = e[1].getECPointData(c);
		int sumTotal = 0;

		int average = (sizeOfRepayment) / repayments;
		for(int i = 0; i < repayments; i++) {
			sumTotal += totalRepaymentValues[i];
			if(totalRepaymentValues[i] < (min)*units) throw new InputMismatchException("Total Repayment Plan entry " + i + " is too small.");
			if(totalRepaymentValues[i] > (max)*units) throw new InputMismatchException("Total Repayment Plan entry " + i + " is too large.");
		}
		if(sumTotal < sizeOfRepayment * units) throw new InputMismatchException("Total repayment table does not conform to the number of units and the size of repayment");
		int colAverage[] = new int[repayments];
		int counter = 0;
		System.out.println(0);
		table = new ECPoint[units][repayments];		
		uncommittedTable = new int[units][repayments];
		keys = new BigInteger[units][repayments];
		int[] colSums = new int[repayments];
		int[] rowSums = new int[units];
		for(int i = 0; i < repayments; i++)
		{
			int totalAverage = totalRepaymentValues[i]/units;
			colAverage[i] = totalAverage;
			int totalRemainder = totalRepaymentValues[i] - totalAverage*units;

			for(int j = 0; j < units; j++)
			{
				uncommittedTable[j][i] = totalAverage;
			}
			for(;totalRemainder > 0; totalRemainder--)
			{
				uncommittedTable[i][counter]++;
				counter = (counter + 1) % units;
			}
			for(int j = 0; j < units; j++)
			{
				colSums[i] += uncommittedTable[j][i];
				rowSums[j] += uncommittedTable[j][i];
			}
		}

		System.out.println(1);
		//Double check table
		//		for(int i = 0; i < repayments; i++)
		//		{
		//			if(colSums[i] != totalRepaymentTable[i])
		//				System.out.println("Bad!!!!  i = " + i + ", " + colSums[i] + " != " + totalRepaymentTable[i]);
		//		}
		//		for(int j = 0; j < units; j++)
		//		{
		//			if(rowSums[j] != sizeOfRepayment)
		//				System.out.println("Bad!!!!  j = " + j + ", " + rowSums[j] + " != " + sizeOfRepayment);
		//		}
		//		
//		for(int i = 0; i < repayments; i++)
//		{
//			//			System.out.println(Arrays.toString(uncommittedTable[i]));
//		}

		//		System.out.println(Arrays.toString(totalRepaymentTable));

		BigInteger order = c.getOrder();
		//Commit the values.
		for(int i = 0; i < repayments; i++)
		{
			for(int j = 0; j < units;j++) {
				do {
					keys[j][i] = new BigInteger(order.bitLength(), rand);
				}while(keys[j][i].compareTo(order) >= 0);
				table[j][i] = g.multiply(BigInteger.valueOf(uncommittedTable[j][i])).add(h.multiply(keys[j][i]));
			}
		}
	}
	
	public void createRawTableProofs(SecureRandom rand, CryptoData environment, ObjectOutputStream out) throws IOException{
		
		if(out == null) throw new NullPointerException("out is null");
		CryptoData[] tableSerializable = new CryptoData[table.length];
		for(int i = 0; i < table.length; i++)
		{
			tableSerializable[i] = new CryptoDataArray(table[i]);
		}
		out.writeObject(new CryptoDataArray(tableSerializable));
		out.writeObject(totalRepaymentTable);
		CryptoData[] e = environment.getCryptoDataArray();
		ECCurve c = e[0].getECCurveData();
		BigInteger order = c.getOrder();
		ECPoint g = e[0].getECPointData(c);
		ECPoint h = e[1].getECPointData(c);
		ZKPProtocol schnorr = new ECSchnorrProver();
		ZKPProtocol[] unpackedRows = new ZKPProtocol[units];
		CryptoData[] rowPublicInputs = new CryptoData[units];
		CryptoData[] rowPrivateInputs = new CryptoData[units];
		CryptoData reversedEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, h), new ECPointData(g)});
		CryptoData[] rowEnv = new CryptoData[units];
		for(int i = 0; i < units; i++)
		{
			unpackedRows[i] = schnorr;
			BigInteger keySum = BigInteger.ZERO;
			ECPoint commProduct = c.getInfinity();
			for(int j = 0; j < repayments; j++)
			{
				commProduct = commProduct.add(table[i][j]);
				keySum = keySum.add(keys[i][j]);
			}
			BigInteger r;
			do {
				r = new BigInteger(order.bitLength(), rand);
			}while(r.compareTo(order) >= 0);
			rowPublicInputs[i] = new CryptoDataArray(new CryptoData[] {new ECPointData(commProduct.subtract(g.multiply(BigInteger.valueOf(sizeOfRepayment))))});
			rowPrivateInputs[i] = new CryptoDataArray(new CryptoData[] {new BigIntData(r), new BigIntData(keySum)});
			rowEnv[i] = reversedEnv;
		}
		ZKPProtocol rowProver = new ZeroKnowledgeAndProver(unpackedRows);
		CryptoData[] rowProof = null;
		
		try {
			System.out.println("Creating Proof ROWS");
			rowProof = rowProver.proveFiatShamir(new CryptoDataArray(rowPublicInputs), new CryptoDataArray(rowPrivateInputs), new CryptoDataArray(rowEnv));
			if(out != null) {
				try {
					out.writeObject(rowProof);
				}
				catch(IOException e1){
				}
			}
			//			System.out.println(proof[0]);
			//			System.out.println();
			//			System.out.println(proof[1]);
			//BigInteger challenge = rowProver.fiatShamirChallange(new CryptoDataArray(rowPublicInputs), proof[0], new CryptoDataArray(rowEnv));
			if(!rowProver.verifyFiatShamir(new CryptoDataArray(rowPublicInputs), rowProof[0], rowProof[1], new CryptoDataArray(rowEnv))) System.out.println("Bad proof!!");
			//			else System.out.println("Bad Proof");
		} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
				| ArraySizesDoNotMatchException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		ZKPProtocol[] unpackedCols = new ZKPProtocol[repayments];
		CryptoData[] colPublicInputs = new CryptoData[repayments];
		CryptoData[] colPrivateInputs = new CryptoData[repayments];
		CryptoData[] colEnv = new CryptoData[repayments];
		for(int i = 0; i < repayments; i++)
		{
			unpackedCols[i] = schnorr;
			BigInteger keySum = BigInteger.ZERO;
			ECPoint commProduct = c.getInfinity();//ECPedersenCommitment.product(table[i], commitmentEnvironment);			
			for(int j = 0; j < units; j++)
			{
				commProduct = commProduct.add(table[j][i]);
				keySum = keySum.add(keys[j][i]);
			}
			BigInteger r;
			do {
				r = new BigInteger(order.bitLength(), rand);
			}while(r.compareTo(order) >= 0);
			colPublicInputs[i] = new CryptoDataArray(new CryptoData[] {new ECPointData(commProduct.subtract(totalRepaymentTable[i].getCommitment(environment)))});
			colPrivateInputs[i] = new CryptoDataArray(new CryptoData[] {new BigIntData(r), new BigIntData(keySum.subtract(totalRepaymentKeys[i]))});
			colEnv[i] = reversedEnv;
		}
		ZKPProtocol colProver = new ZeroKnowledgeAndProver(unpackedCols);
		CryptoData[] colProof = null;

		try {
			System.out.println("Creating Proof COLS");
			colProof = colProver.proveFiatShamir(new CryptoDataArray(colPublicInputs), new CryptoDataArray(colPrivateInputs), new CryptoDataArray(colEnv));
			if(out != null) {
				try {
					out.writeObject(rowProof);
				}
				catch(IOException e1){
				}
			}
			//			System.out.println(proof[0]);
			//			System.out.println();
			//			System.out.println(proof[1]);
			//BigInteger challenge = rowProver.fiatShamirChallange(new CryptoDataArray(rowPublicInputs), proof[0], new CryptoDataArray(rowEnv));
			if(!colProver.verifyFiatShamir(new CryptoDataArray(colPublicInputs), colProof[0], colProof[1], new CryptoDataArray(colEnv))) System.out.println("Bad proof!!");
			//			else System.out.println("Bad Proof");
		} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
				| ArraySizesDoNotMatchException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		CryptoData[][][] rangeProofs = new CryptoData[units][repayments][];
		for(int i = 0; i < repayments; i++) {
			System.out.println("Running columns " + i);
			for(int j = 0; j < units; j++) {
				rangeProofs[j][i] = ZKToolkit.rangeProofFiatShamirConstruction(BigInteger.valueOf(uncommittedTable[j][i]), keys[j][i], BigInteger.valueOf(min), BigInteger.valueOf(max), environment, rand);
				//				System.out.println();
				//				System.out.println(rangeProofs[j][i][1]);
				//				System.out.println(Integer.toBinaryString(uncommittedTable[j][i]-min));
				//				System.out.println(BigInteger.valueOf(max).subtract(BigInteger.valueOf(min)).bitLength());
				if(!ZKToolkit.rangeProofFiatShamirVerify(new ECPointData(table[j][i]), rangeProofs[j][i], BigInteger.valueOf(min),  BigInteger.valueOf(max), environment))  System.out.println("Bad range proof :-(");
			}
		}
		if(out != null) {
			try {
				out.writeObject(rangeProofs);
				out.flush(); 
			}
			catch(IOException e1){
			}
		}
		
	}
	public void consolidateTable(int numInvestors, boolean[][] mappingTableValues, BigInteger[][] mappingTableKeys, ECPoint[][] mappingTable, int[] mValues, BigInteger[] mKeys, ECPoint[] mTable, SecureRandom rand, ObjectOutputStream publicOut, CryptoData environment) {
		this.numInvestors = numInvestors;
		ZKPProtocol schnorr = new ECSchnorrProver();
		CryptoData[] e = environment.getCryptoDataArray();
		ECCurve c = e[0].getECCurveData();
		BigInteger order = c.getOrder();
		ECPoint g = e[0].getECPointData(c);
		ECPoint h = e[1].getECPointData(c);
		CryptoData revEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, h)});
		//First, prove the mapping table is a mapping table
		//To do this, rows add to 1
		for(int i = 0; i < units; i++) {
			ECPoint totalComm = c.getInfinity();
			BigInteger totalKey = BigInteger.ZERO;
			for(int j = 0; j < numInvestors; j++) {
				totalComm = totalComm.add(mappingTable[i][j]);
				totalKey = totalKey.add(mappingTableKeys[i][j]);
			}
			CryptoData publicInputs = new CryptoDataArray(new CryptoData[] {new ECPointData(totalComm.subtract(g))});
			CryptoData privateInputs = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand), totalKey});
			CryptoData[] result = null;
			try {
				result = schnorr.proveFiatShamir(publicInputs, privateInputs, revEnv);
				publicOut.writeObject(result);
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			try {
				if(!schnorr.verifyFiatShamir(publicInputs, result[0], result[1], revEnv)) System.out.println("Bad Proof on Rows!");
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		
		//Then, prove the cols add to m_j
		for(int j = 0; j < numInvestors; j++) {
			ECPoint totalComm = mappingTable[0][j];
			BigInteger totalKey = mappingTableKeys[0][j];
			for(int i = 1; i < units; i++) {
				totalComm = totalComm.add(mappingTable[i][j]);
				totalKey = totalKey.add(mappingTableKeys[i][j]);
			}
			CryptoData publicInputs = new CryptoDataArray(new CryptoData[] {new ECPointData(totalComm.subtract(mTable[j]))});
			CryptoData privateInputs = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand), totalKey.subtract(mKeys[j])});
			CryptoData[] result = null;
			try {

				result = schnorr.proveFiatShamir(publicInputs, privateInputs, revEnv);
				publicOut.writeObject(result);
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			try {
				if(!schnorr.verifyFiatShamir(publicInputs, result[0], result[1], revEnv)) System.out.println("Bad Proof on Cols!");
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		
		//Now, we consolidate the raw table.  Part of this proves each cell is 0 or 1
		
		CryptoData[] largeEnvInner = new CryptoData[numRepayment+1];
		ZKPProtocol[] largeProofAndUnpacked = new ZKPProtocol[numRepayment+1];
		
		for(int j = 0; j < numRepayment+1; j++) {
			largeEnvInner[j] = revEnv;
			largeProofAndUnpacked[j] = schnorr;
		}
		ZKPProtocol largeProofAnd = new ZeroKnowledgeAndProver(largeProofAndUnpacked);
		ZKPProtocol largeProof = new ZeroKnowledgeOrProver(new ZKPProtocol[] {largeProofAnd,largeProofAnd});

		CryptoData largeEnvInnerPacked = new CryptoDataArray(new CryptoData[]{new CryptoDataArray(largeEnvInner)});
		CryptoData largeEnv = new CryptoDataArray(new CryptoData[] {largeEnvInnerPacked, largeEnvInnerPacked});
		ECPoint[][][] vHat = new ECPoint[numInvestors][numRepayment][units];
		BigInteger[][][] vKeys = new BigInteger[numInvestors][numRepayment][units];
		
		for(int k = 0; k < numInvestors; k++) {
			for(int i = 0; i < units; i++){
				CryptoData[] innerPublicData0 = new CryptoData[numRepayment+1];
				CryptoData[] innerPrivateData0 = new CryptoData[numRepayment+1];
				CryptoData[] innerPublicData1 = new CryptoData[numRepayment+1];
				CryptoData[] innerPrivateData1 = new CryptoData[numRepayment+1];
				CryptoData[] middlePrivateData = new CryptoData[3];
				CryptoData[] middlePublicData = new CryptoData[2];
				
				if(mappingTableValues[k][i]) {
					for(int j = 0; j < numRepayment; j++) {
						vKeys[k][j][i] = ZKToolkit.random(order, rand);
						vHat[k][j][i] = g.multiply(BigInteger.valueOf(uncommittedTable[i][j])).add(h.multiply(vKeys[k][j][i]));
						innerPublicData0[j] = new CryptoDataArray(new CryptoData[] {new ECPointData(vHat[k][j][i])});
						innerPrivateData0[j] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand)});
						innerPublicData1[j] = new CryptoDataArray(new CryptoData[] {new ECPointData(vHat[k][j][i].subtract(table[i][j]))});
						innerPrivateData1[j] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand), vKeys[k][j][i].subtract(keys[i][j])});
						consolidatedTableValues[k][j] += uncommittedTable[i][j];
						try {
							publicOut.writeObject(vHat[k][j][i]);
						} catch (IOException e1) {
							e1.printStackTrace();
						}
					}
					innerPublicData0[numRepayment] = new CryptoDataArray(new CryptoData[] {new ECPointData(mappingTable[k][i])});
					innerPrivateData0[numRepayment] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand)});
					innerPublicData1[numRepayment] = new CryptoDataArray(new CryptoData[] {new ECPointData(mappingTable[k][i].subtract(g))});
					innerPrivateData1[numRepayment] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand), mappingTableKeys[k][i]});
					
					middlePrivateData[0] = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPrivateData0)});
					middlePrivateData[1] = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPrivateData1)});
					middlePrivateData[2] = new CryptoDataArray(new BigInteger[] {new BigInteger(order.bitLength()-1, rand), BigInteger.ZERO});
					middlePublicData[0] =  new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPublicData0)});
					middlePublicData[1] =  new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPublicData1)});
				}else {
					for(int j = 0; j < numRepayment; j++) {
						vKeys[k][j][i] = ZKToolkit.random(order, rand);
						vHat[k][j][i] = h.multiply(vKeys[k][j][i]);
						innerPublicData0[j] = new CryptoDataArray(new CryptoData[] {new ECPointData(vHat[k][j][i])});
						innerPrivateData0[j] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand), vKeys[k][j][i]});
						innerPublicData1[j] = new CryptoDataArray(new CryptoData[] {new ECPointData(vHat[k][j][i].subtract(table[i][j]))});
						innerPrivateData1[j] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand)});
						consolidatedTableValues[k][j] += uncommittedTable[i][j];
						try {
							publicOut.writeObject(vHat[k][j][i]);
						} catch (IOException e1) {
							e1.printStackTrace();
						}
					}
					innerPublicData0[numRepayment] = new CryptoDataArray(new CryptoData[] {new ECPointData(mappingTable[k][i])});
					innerPrivateData0[numRepayment] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand), mappingTableKeys[k][i]});
					innerPublicData1[numRepayment] = new CryptoDataArray(new CryptoData[] {new ECPointData(mappingTable[k][i].subtract(g))});
					innerPrivateData1[numRepayment] = new CryptoDataArray(new BigInteger[] {ZKToolkit.random(order, rand)});
					
					middlePrivateData[0] = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPrivateData0)});
					middlePrivateData[1] = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPrivateData1)});
					middlePrivateData[2] = new CryptoDataArray(new BigInteger[] {BigInteger.ZERO, new BigInteger(order.bitLength()-1, rand)});
					middlePublicData[0] =  new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPublicData0)});
					middlePublicData[1] =  new CryptoDataArray(new CryptoData[] {new CryptoDataArray(innerPublicData1)});
				}
				CryptoData[] transcript = null;
				try {
					transcript = largeProof.proveFiatShamir(new CryptoDataArray(middlePublicData), new CryptoDataArray(middlePrivateData), largeEnv);
				} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
						| ArraySizesDoNotMatchException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				try {
					if(largeProof.verifyFiatShamir(new CryptoDataArray(middlePublicData), transcript[0], transcript[1], environment)) System.out.println("Bad Proof on large proof");
				} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
						| ArraySizesDoNotMatchException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		}
		
	}
}
