package varianceprotocol;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Date;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;



public class ECKeyMakerMultiSig {
	public static void main(String[] args) throws Exception
	{
		Encoder encoder = Base64.getEncoder();
		System.out.println(new Date());
		final long startTime = System.currentTimeMillis();
		//Usage:  <executable> <namesCurve> <numKeys> <ProportionOfOwnedKeys> <ProportionOfOwnedKeysOwnedByP1> <n> <k> [Last file] [Seed]
		ECPoint g = ECNamedCurveTable.getParameterSpec(args[0]).getG();
		SecureRandom r = new SecureRandom();
		int numKeys = Integer.parseInt(args[1]);
		int start = 0;
		Writer arg0 = null;
		BufferedWriter out, out2, out3, out4;
		if(args.length >= 7 && args[6] != null && args[6] != "0" && args[6] != "")
		{
			int last = Integer.parseInt(args[6]);
			if(last <= numKeys)
			{
				Files.copy(new File("P1Keys" + args[6] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), new File("P1Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				Files.copy(new File("Account" + args[6] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), new File("Account" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				Files.copy(new File("P2Keys" + args[6] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), new File("P2Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				Files.copy(new File("Keys" + args[6] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), new File("Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				start = last;
				try {
					arg0 = new FileWriter("Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3], true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				out = new BufferedWriter(arg0);

				try {
					arg0 = new FileWriter("Account" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3], true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				out2 = new BufferedWriter(arg0);

				try {
					arg0 = new FileWriter("P1Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3], true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				out3 = new BufferedWriter(arg0);

				try {
					arg0 = new FileWriter("P2Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3], true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	
				out4 = new BufferedWriter(arg0);

			}
			else
			{
				throw new Exception();
			}
		}
		else
		{
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
			
			try {
				arg0 = new FileWriter("P1Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			out3 = new BufferedWriter(arg0);
			
			try {
				arg0 = new FileWriter("P2Keys" + args[1] + "_" + args[4] + "_" + args[5] + "_" + args[2] + "_" + args[3]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			out4 = new BufferedWriter(arg0);
		}
		int n = Integer.parseInt(args[2]);
		int k = Integer.parseInt(args[3]);
		System.out.println(k);
		double pOwned = Double.parseDouble(args[4]);
		System.out.println(pOwned);
		if(pOwned > 1 || pOwned < 0) throw new Exception("Must be between 0 and 1");
		double pOwnedByP1 = Double.parseDouble(args[5]);
		if(pOwnedByP1 > 1 || pOwnedByP1 < 0) throw new Exception("Must be between 0 and 1");
		
		System.out.println("Generating Keys (" + numKeys + ")");
		BigInteger[][][] results = keyMaster(g, numKeys - start, n, r);
		System.out.println("Writing Keys");
		out.write("//(Private Keys		Public Key)*\n");
		out2.write("//Account Balance		n		k		Public Keys\n");
		out3.write("//Account Line		Private Keys\n");
		out4.write("//Account Line		Private Keys\n");
		StringBuilder keyFile = new StringBuilder();
		StringBuilder accountFile = new StringBuilder();
		StringBuilder ownedKeys = new StringBuilder();
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
				ownedKeys.setLength(0);				
				ownedKeys.append(i);
				ownedKeys.append("\t");		
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
					for(int l = 0; l < k - j -1; l++)
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
					ownedKeys.append(positions[j]);
					ownedKeys.append("\t");
					ownedKeys.append(encoder.encodeToString((results[i][positions[j]][0]).toByteArray()));
					ownedKeys.append("\t");
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
					out3.write(ownedKeys.toString());
					out3.write("\n");
				}
				else 
				{
					out4.write(ownedKeys.toString());
					out4.write("\n");
				}
			}
		}
			//String toWriteY = Base64.getEncoder().encodeToString(results[i][2].toByteArray());
//			out.write(String.format("%s\t%s\n", toWrite0, toWriteP));
//			out2.write(String.format("%s\t%s\n", new BigInteger(10, r).toString(16),toWriteP));
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
		out3.flush();
		out4.flush();
		out.close();
		out2.close();
		out3.close();
		out4.close();
		final long endTime = System.currentTimeMillis();
		System.out.println("Time (ms): " + (endTime - startTime));
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

