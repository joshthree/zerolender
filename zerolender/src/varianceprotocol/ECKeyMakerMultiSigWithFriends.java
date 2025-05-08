package varianceprotocol;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Date;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;



public class ECKeyMakerMultiSigWithFriends {
	public static void main(String[] args) throws Exception
	{
		Encoder encoder = Base64.getEncoder();
		System.out.println(new Date());
		final long startTime = System.currentTimeMillis();
		//Usage:  <executable> <namesCurve> <numKeys>  <n> <k> <ProportionOfOwnedKeys> <ProportionOfOwnedKeysOwnedByP1> [Seed]
		ECPoint g = ECNamedCurveTable.getParameterSpec(args[0]).getG();
		SecureRandom r = new SecureRandom();
		int numKeys = Integer.parseInt(args[1]);
		int start = 0;
		Writer arg0 = null;
		int n = Integer.parseInt(args[2]);
		int k = Integer.parseInt(args[3]);
		if(n < k) {
			System.out.println("n is less than k");
			System.exit(1);
		}
		BufferedWriter[] p1Out = new BufferedWriter[k];
		BufferedWriter[] p2Out = new BufferedWriter[k];
		
		BufferedWriter out = null, out2 = null;

		try {
			arg0 = new FileWriter("Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		out = new BufferedWriter(arg0);
		
		try {
			arg0 = new FileWriter("Account" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		out2 = new BufferedWriter(arg0);
		

		for(int i = 0; i < k; i++)
		{

			try {
				arg0 = new FileWriter("P1." + i + "_Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]);
			} catch (IOException e) {
				e.printStackTrace();
			}
			p1Out[i] = new BufferedWriter(arg0);
			try {
				arg0 = new FileWriter("P2." + i + "_Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]);
			} catch (IOException e) {
				e.printStackTrace();
			}
			p2Out[i] = new BufferedWriter(arg0);
		}
		//System.out.println(k);
		double pOwned = Double.parseDouble(args[4]);
		//System.out.println(pOwned);
		if(pOwned > 1 || pOwned < 0) throw new Exception("Must be between 0 and 1");
		double pOwnedByP1 = Double.parseDouble(args[5]);
		if(pOwnedByP1 > 1 || pOwnedByP1 < 0) throw new Exception("Must be between 0 and 1");
		
		System.out.println("Generating Keys (" + numKeys + ")");
		BigInteger[][][] results = keyMaster(g, numKeys - start, n, r);
		System.out.println("Writing Keys");
		out.write("//(Private Keys		Public Key)*\n");
		out2.write("//Account Balance		n		k		Public Keys\n");
		StringBuilder keyFile = new StringBuilder();
		StringBuilder accountFile = new StringBuilder();
		StringBuilder ownedKeys[] = new StringBuilder[k];
		int[] order;
		for(int j = 0; j < ownedKeys.length; j++)
		{
			ownedKeys[j] = new StringBuilder();
		}
		double x;
		double p = 0;
		int[] positions = new int[k]; 
		for(int i = 0; i < numKeys - start; i++)
		{
			BigInteger balance =  new BigInteger(10, r);
			keyFile.setLength(0);
			accountFile.setLength(0);
			x = r.nextDouble();
			if(x < pOwned)
			{
				p = r.nextDouble();

				for(int j = 0; j < ownedKeys.length; j++)
				{
					ownedKeys[j].setLength(0);				
					ownedKeys[j].append(i);
					ownedKeys[j].append("\t");		
				}
			}
			accountFile.append(balance.toString(16));
			accountFile.append("\t");
			accountFile.append(n);
			accountFile.append("\t");
			accountFile.append(k);
			accountFile.append("\t");
			
			for(int j = 0; j < n; j++)
			{
				keyFile.append("(");
				keyFile.append(encoder.encodeToString(results[i][j][0].toByteArray()));
				keyFile.append(", ");
				keyFile.append(encoder.encodeToString(results[i][j][1].toByteArray()));
				keyFile.append(")");
				if(j != n-1) keyFile.append(", ");
				
				accountFile.append(encoder.encodeToString(results[i][j][1].toByteArray()));
				accountFile.append("\t");
				
			}
			order = new int[k];
			for(int j = 1; j < k; j++)
			{
				while(true)
				{
					int random = r.nextInt(k);
					if(order[random] == 0)
					{
						order[random] = j;
						break;
					}
				}
				
			}
			if(x < pOwned)
			{
				for(int j = 0; j < k; j++)
				{
					positions[j] = r.nextInt(n);
					boolean flag = true;
					while(flag)
					{
						flag = false;
						for(int l = 0; l < j; l++)
						{
							if(positions[l] == positions[j])
							{
								positions[j] = r.nextInt(n);
								flag = true;
								break;
							}
						}
					}
				}
				for(int j = 0; j < k - 1; j++)
				{
					for(int l = 0; l < k - j - 1; l++)
					{
						if(positions[l] > positions[l+1])
						{
							int temp = positions[l+1];
							positions[l+1] = positions[l];
							positions[l] = temp;
						}
					}
				}
				for(int j = 0; j < k; j++)
				{
					
					if(order[j] != 0)
					{
						ownedKeys[0].append("-" + positions[j] + "\t" + order[j] + "\t");
						
					}
					ownedKeys[order[j]].append(positions[j]);			
					ownedKeys[order[j]].append("\t");
					ownedKeys[order[j]].append(encoder.encodeToString((results[i][positions[j]][0]).toByteArray()));
					ownedKeys[order[j]].append("\t");
				}
			}
			out.write(keyFile.toString());
			out.write("\n");
			out2.write(accountFile.toString());
			out2.write("\n");
			if(x < pOwned)
			{
				if(p < pOwnedByP1) 
				{
					for(int j = 0; j < k; j++)
					{
						p1Out[j].write(ownedKeys[j].toString());
						p1Out[j].write("\n");
					}
				}
				else 
				{
					for(int j = 0; j < k; j++)
					{
						p2Out[j].write(ownedKeys[j].toString());
						p2Out[j].write("\n");
					}
				}
			}
		}
//			if(r.nextDouble() < pOwned)
//			{
//				if(r.nextDouble() < pOwnedByP1)
//				{
//					out3.write(String.format("%s\t%s\n", toWrite0, toWriteP));
//				}
//				else
//				{
//					out4.write(String.format("%s\t%s\n", toWrite0, toWriteP));
//				}
//			}
			
		out.flush();
		out2.flush();
		for(int i = 0; i < k; i++)
		{
			p1Out[i].flush();
			p2Out[i].flush();
		}
		out.close();
		out2.close();
		final long endTime = System.currentTimeMillis();
		System.out.println("Time (ms): " + (endTime - startTime));
		for(int i = 0; i < k; i++)
		{
			p1Out[i].close();
			p2Out[i].close();
		}
	}
	public static BigInteger[][][] keyMaster(ECPoint g, int numKeys, int n, SecureRandom r)
	{
		BigInteger[][][] toReturn = new BigInteger[numKeys][][];
		int numBits = g.getCurve().getOrder().bitLength();
		for(int i = 0; i < numKeys; i++)
		{
			toReturn[i] = new BigInteger[n][];
			for(int j = 0; j < n; j++)
			{
				BigInteger privateKey;
				do {
					privateKey = new BigInteger(numBits, r);
				}while(privateKey.compareTo(g.getCurve().getOrder()) >= 0);
				ECPoint publicKey = g.multiply(privateKey);
				
				//publicKey.getAffineXCoord().toBigInteger();
				//publicKey.getAffineYCoord().toBigInteger();
				
				toReturn[i][j] = new BigInteger[] {privateKey, new BigInteger(publicKey.getEncoded(true))};
			}
		}
		return toReturn;
	}
}

