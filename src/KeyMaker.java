import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.util.encoders.Base64;


public class KeyMaker {
	public static void main(String[] args) throws Exception
	{
		//Usage:  <executable> <p> <g> <numKeys> <ProportionOfOwnedKeys> <ProportionOfOwnedKeysOwnedByP1> [Seed]
		BigInteger p = new BigInteger(args[0]);
		BigInteger g = new BigInteger(args[1]);
		Random r;  
		if(args.length == 6)
			r = new SecureRandom(new BigInteger(args[5]).toByteArray());
		else
			r = new SecureRandom();
		
		Writer arg0 = null;
		try {
			arg0 = new FileWriter("Keys" + args[2] + "_" + args[3] + "_" + args[4]);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		BufferedWriter out = new BufferedWriter(arg0);
		
		try {
			arg0 = new FileWriter("Account" + args[2] + "_" + args[3] + "_" + args[4]);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		BufferedWriter out2 = new BufferedWriter(arg0);

		try {
			arg0 = new FileWriter("P1Keys" + args[2] + "_" + args[3] + "_" + args[4]);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		BufferedWriter out3 = new BufferedWriter(arg0);

		try {
			arg0 = new FileWriter("P2Keys" + args[2] + "_" + args[3] + "_" + args[4]);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		BufferedWriter out4 = new BufferedWriter(arg0);
		
		double pOwned = Double.parseDouble(args[3]);
		if(pOwned > 1 || pOwned < 0) throw new Exception("Must be between 0 and 1");
		double pOwnedByP1 = Double.parseDouble(args[4]);
		if(pOwnedByP1 > 1 || pOwnedByP1 < 0) throw new Exception("Must be between 0 and 1");
		
		int numKeys = Integer.parseInt(args[2]);
		System.out.println("Generating Keys");
		BigInteger[][] results = keyMaster(p, g, numKeys, r);
		System.out.println("Writing Keys");
		out.write("//Private Key		Public Key\n");
		out2.write("//Account Balance		Public Key\n");
		out3.write("//Private Key		Owned Public Key\n");
		out4.write("//Private Key		Owned Public Key\n");
		for(int i = 0; i < numKeys; i++)
		{
			String toWrite0 = Base64.toBase64String(results[i][0].toByteArray());
			String toWrite1 = Base64.toBase64String(results[i][1].toByteArray());
			System.out.println(results[i][0]);
			System.out.println(toWrite0);
			out.write(String.format("%s\t%s\n", toWrite0, toWrite1));
			out2.write(String.format("%s\t%s\n", new BigInteger(10, r),toWrite1));
			if(r.nextDouble() < pOwned)
			{
				if(r.nextDouble() < pOwnedByP1)
				{
					out3.write(String.format("%s\t%s\n", toWrite0, toWrite1));
				}
				else
				{
					out4.write(String.format("%s\t%s\n", toWrite0,toWrite1));
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
	}
	public static BigInteger[][] keyMaster(BigInteger p, BigInteger g, int numKeys, Random r)
	{
		BigInteger[][] toReturn = new BigInteger[numKeys][];
		for(int i = 0; i < numKeys; i++)
		{
			
			BigInteger privateKey;
			do {
				privateKey = new BigInteger(p.bitLength(), r);
			}while(privateKey.compareTo(p.subtract(BigInteger.ONE)) >= 0);
			
			BigInteger publicKey = g.modPow(privateKey, p);
			
			toReturn[i] = new BigInteger[] {privateKey, publicKey};
		}
		return toReturn;
	}
}

