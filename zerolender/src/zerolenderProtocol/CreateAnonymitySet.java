package zerolenderProtocol;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class CreateAnonymitySet {
	public static void main(String[] args) throws FileNotFoundException, IOException {
		//numAccounts, investorAmounts
		if(args.length < 2) {
			System.out.println("Usage:  java -cp \"./bin;./jars/*\" zeroLender.CreateAnonymousSet numAccounts max baseFileName [repaymentAmount]* ");
			System.exit(0);
		}
		int numAccounts = Integer.parseInt(args[0]);
		int max = Integer.parseInt(args[1]);
		String baseFileName = args[2];
		int[] investorAmounts = new int[args.length-3];
		
		SecureRandom rand = new SecureRandom();
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		ECCurve curve = g.getCurve();
		BigInteger order = g.getCurve().getOrder();
		BigInteger random;
		do {
			random = new BigInteger(order.bitLength(), rand);
		}while(random.compareTo(order) >= 0);
		ECPoint h = g.multiply(random);
		
		int numInvestors = investorAmounts.length;
		
		BigInteger[] clientKeys = new BigInteger[numInvestors];
		BigInteger[] clientAddresses = new BigInteger[numInvestors];
		ECPoint[] clientCommitments = new ECPoint[numInvestors];
		
		
		BigInteger[] addresses = new BigInteger[numAccounts];
		BigInteger[] accountPrivateKeys = new BigInteger[numAccounts];
		ECPoint[] accountPublicKeys = new ECPoint[numAccounts];
		int[] owner = new int[numAccounts];
		
		SecureRandom r = new SecureRandom();
		
		int[] amounts = new int[numAccounts];
		ObjectOutputStream mainOut = new ObjectOutputStream(new FileOutputStream(new File(baseFileName)));
		ObjectOutputStream mainPub = new ObjectOutputStream(new FileOutputStream(new File(baseFileName+ "_pub")));
		ObjectOutputStream mainPriv = new ObjectOutputStream(new FileOutputStream(new File(baseFileName+ "_priv")));
//		ObjectOutputStream priv = new ObjectOutputStream[numInvestors];
//		mainOut.writeObject(new ECPointData(h));
		mainOut.writeInt(numAccounts);
		for(int i = 0; i < numInvestors; i++) {
//			priv[i] = new ObjectOutputStream(new FileOutputStream(new File(baseFileName+ "_" + i)));
			clientAddresses[i] = new BigInteger(192, r).add(BigInteger.valueOf(r.nextInt()*2+1).shiftLeft(192));
			clientKeys[i] = ZKToolkit.random(order, r);
			clientCommitments[i] = g.multiply(clientAddresses[i]).add(h.multiply(clientKeys[i]));
		}
		
		int totalInvestorTransactions = 0;
		
		int counter = 0;
		for(int i = 0; i < investorAmounts.length; i++) {
//			BigInteger address = new BigInteger(192, r).add(BigInteger.valueOf(r.nextInt()*2+1).shiftLeft(192));
			investorAmounts[i] = Integer.parseInt(args[i+3]);
			if(investorAmounts[i] == 0) continue;
//			int numTransactions = rand.nextInt(5) + 1;
			int numTransactions = 1;
			totalInvestorTransactions += numTransactions;
			if(numTransactions == 1) {
				accountPrivateKeys[counter] = ZKToolkit.random(order, r);
				accountPublicKeys[counter] = g.multiply(accountPrivateKeys[counter]);
				amounts[counter] = investorAmounts[i];
				addresses[counter] = clientAddresses[i];
				owner[counter] = i;
				
				counter++;
			}else {
				double[] proportions = new double[numTransactions];
				double totalDouble = 0;
				int[] total = new int[numTransactions];
				int totalInt = 0;
				
				for(int j = 0; j < numTransactions; j++) {
					totalDouble += proportions[j] = r.nextDouble();
				}
				for(int j = 0; j < numTransactions; j++) {
					totalInt += total[j] /= totalDouble * investorAmounts[i];
				}
				
				while(totalInt <investorAmounts[i])
				{
					total[r.nextInt(numTransactions)]++;
					totalInt++;
				}
				for(int j = 0; j < numTransactions; j++) {
					accountPrivateKeys[counter] = ZKToolkit.random(order, r);
					accountPublicKeys[counter] = g.multiply(accountPrivateKeys[counter]);
					amounts[counter] = total[j];
					addresses[counter] = clientAddresses[i];
					owner[counter] = i;
					counter++;
				}
			}
		}
		for(int i = counter; i < numAccounts; i++) {
//			accountPrivateKeys[i] = ZKToolkit.random(order, r);
//			accountPublicKeys[i] = g.multiply(accountPrivateKeys[counter]);
			accountPublicKeys[i] = g.multiply(ZKToolkit.random(order, r));
			amounts[i] = r.nextInt(max-1) + 1;
			addresses[i] = new BigInteger(192, r).add(BigInteger.valueOf(r.nextInt()*2+1).shiftLeft(192));
			owner[i] = -1;
		}

		for(int k = 0; k < numAccounts; k++) {
			if(owner[k] != -1) {
				if(!clientCommitments[owner[k]].equals(g.multiply(addresses[k]).add(h.multiply(clientKeys[owner[k]])))) {
					System.out.println("is it here?");
				}
			}
		}
		for(int i = numAccounts-1; i > 0; i--) {
			int num = rand.nextInt(i+1);
			
			BigInteger temp1 = accountPrivateKeys[i];
			accountPrivateKeys[i] = accountPrivateKeys[num];
			accountPrivateKeys[num] = temp1;
			
			temp1 = addresses[i];
			addresses[i] = addresses[num];
			addresses[num] = temp1;
			
			ECPoint temp2 = accountPublicKeys[i];
			accountPublicKeys[i] = accountPublicKeys[num];
			accountPublicKeys[num] = temp2;
			
			int temp3 = owner[i];
			owner[i] = owner[num];
			owner[num] = temp3;
			
			temp3 = amounts[i];
			amounts[i] = amounts[num];
			amounts[num] = temp3;
		}
		for(int k = 0; k < numAccounts; k++) {
			if(owner[k] != -1) {
				if(!clientCommitments[owner[k]].equals(g.multiply(addresses[k]).add(h.multiply(clientKeys[owner[k]])))) {
					System.out.println("There's the problem");
				}
			}
		}
		mainPub.writeObject(new ECPointData(h));
		ECPoint[] amountCommitments = new ECPoint[numInvestors];
		BigInteger[] amountKeys = new BigInteger[numInvestors];
		for(int i = 0; i < numInvestors; i++) {
			amountKeys[i] = ZKToolkit.random(order, r);
			BigInteger m = BigInteger.valueOf(investorAmounts[i]);
			amountCommitments[i] = g.multiply(m).add(h.multiply(amountKeys[i]));
		}
		mainPub.writeObject(new CryptoDataArray(clientCommitments));
		mainPub.writeObject(new CryptoDataArray(amountCommitments));
		
		
		mainPriv.writeObject(clientAddresses);
		mainPriv.writeObject(clientKeys);
		
		mainPriv.writeInt(totalInvestorTransactions);
		mainPriv.writeObject(investorAmounts);
		mainPriv.writeObject(amountKeys);
		
		for(int i = 0; i < numAccounts; i++) {
			mainOut.writeObject(addresses[i]);
			mainOut.writeObject(new ECPointData(accountPublicKeys[i]));
			mainOut.writeInt(amounts[i]);
			mainOut.flush();
//			mainOut.writeObject(obj);
			if(owner[i] != -1) {
				mainPriv.writeInt(i);
				mainPriv.writeInt(owner[i]);
				mainPriv.writeObject(accountPrivateKeys[i]);
				
			}
		}
		mainOut.flush();
		mainOut.close();
		mainPub.flush();
		mainPub.close();
		mainPriv.flush();
		mainPriv.close();
		System.out.println("List Created!");
	}
	
}
