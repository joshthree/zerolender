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
import java.util.Date;
import java.util.Random;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;



public class ECKeyMaker {
	public static void main(String[] args) throws Exception
	{
		System.out.println(new Date());
		final long startTime = System.currentTimeMillis();
		//Usage:  <executable> <namesCurve> <numKeys> <ProportionOfOwnedKeys> <ProportionOfOwnedKeysOwnedByP1> [Last file] [Seed]
		ECPoint g = ECNamedCurveTable.getParameterSpec(args[0]).getG();
		Random r = new SecureRandom();
		int numKeys = Integer.parseInt(args[1]);
		int start = 0;
		Writer arg0 = null;
		BufferedWriter out, out2, out3, out4;
		if(args.length >= 6 && args[5] != null && args[5] != "0" && args[5] != "")
		{
			int last = Integer.parseInt(args[5]);
			if(last <= numKeys)
			{
				Files.copy(new File("P1Keys" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), new File("P1Keys" + args[2] + "_" + args[3] + "_" + args[4]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				Files.copy(new File("Account" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), new File("Account" + args[2] + "_" + args[3] + "_" + args[4]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				Files.copy(new File("P2Keys" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), new File("P2Keys" + args[2] + "_" + args[3] + "_" + args[4]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				Files.copy(new File("Keys" + args[5] + "_" + args[2] + "_" + args[3]).toPath(), new File("Keys" + args[2] + "_" + args[3] + "_" + args[4]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				start = last;
				try {
					arg0 = new FileWriter("Keys" + args[1] + "_" + args[2] + "_" + args[3], true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				out = new BufferedWriter(arg0);

				try {
					arg0 = new FileWriter("Account" + args[1] + "_" + args[2] + "_" + args[3], true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				out2 = new BufferedWriter(arg0);

				try {
					arg0 = new FileWriter("P1Keys" + args[1] + "_" + args[2] + "_" + args[3], true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				out3 = new BufferedWriter(arg0);

				try {
					arg0 = new FileWriter("P2Keys" + args[1] + "_" + args[2] + "_" + args[3], true);
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
				arg0 = new FileWriter("Keys" + args[1] + "_" + args[2] + "_" + args[3]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			out = new BufferedWriter(arg0);
			
			try {
				arg0 = new FileWriter("Account" + args[1] + "_" + args[2] + "_" + args[3]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			out2 = new BufferedWriter(arg0);
			
			try {
				arg0 = new FileWriter("P1Keys" + args[1] + "_" + args[2] + "_" + args[3]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			out3 = new BufferedWriter(arg0);
			
			try {
				arg0 = new FileWriter("P2Keys" + args[1] + "_" + args[2] + "_" + args[3]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			out4 = new BufferedWriter(arg0);
		}
		
		double pOwned = Double.parseDouble(args[2]);
		if(pOwned > 1 || pOwned < 0) throw new Exception("Must be between 0 and 1");
		double pOwnedByP1 = Double.parseDouble(args[3]);
		if(pOwnedByP1 > 1 || pOwnedByP1 < 0) throw new Exception("Must be between 0 and 1");
		
		System.out.println("Generating Keys (" + numKeys + ")");
		BigInteger[][] results = keyMaster(g, numKeys - start, r);
		System.out.println("Writing Keys");
		out.write("//Private Key		Public Key\n");
		out2.write("//Account Balance		Public Key\n");
		out3.write("//Private Key		Owned Public Key\n");
		out4.write("//Private Key		Owned Public Key\n");
		for(int i = 0; i < numKeys - start; i++)
		{
			String toWrite0 = Base64.getEncoder().encodeToString(results[i][0].toByteArray());
			String toWriteP = Base64.getEncoder().encodeToString(results[i][1].toByteArray());
			//String toWriteY = Base64.getEncoder().encodeToString(results[i][2].toByteArray());
			out.write(String.format("%s\t%s\n", toWrite0, toWriteP));
			out2.write(String.format("%s\t%s\n", new BigInteger(10, r).toString(16),toWriteP));
			if(r.nextDouble() < pOwned)
			{
				if(r.nextDouble() < pOwnedByP1)
				{
					out3.write(String.format("%s\t%s\n", toWrite0, toWriteP));
				}
				else
				{
					out4.write(String.format("%s\t%s\n", toWrite0, toWriteP));
				}
			}
			
		}
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
	public static BigInteger[][] keyMaster(ECPoint g, int numKeys, Random r)
	{
		BigInteger[][] toReturn = new BigInteger[numKeys][];
		int numBits = g.getCurve().getOrder().bitLength()-1;
		for(int i = 0; i < numKeys; i++)
		{
			BigInteger privateKey;
			privateKey = new BigInteger(numBits, r);
			ECPoint publicKey = g.multiply(privateKey);
			
			//publicKey.getAffineXCoord().toBigInteger();
			//publicKey.getAffineYCoord().toBigInteger();
			
			toReturn[i] = new BigInteger[] {privateKey, new BigInteger(publicKey.getEncoded(true))};
		}
		return toReturn;
	}
}

