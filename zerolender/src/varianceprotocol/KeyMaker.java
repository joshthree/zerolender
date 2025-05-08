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



public class KeyMaker {
	public static void main(String[] args) throws Exception
	{
		System.out.println(new Date());
		final long startTime = System.currentTimeMillis();
		//Usage:  <executable> <p> <g> <numKeys> <ProportionOfOwnedKeys> <ProportionOfOwnedKeysOwnedByP1> [Last file] [Seed]
		BigInteger p = new BigInteger(args[0]);
		BigInteger g = new BigInteger(args[1]);
		Random r;  
		if(args.length == 7 && args[6] != null)
			r = new SecureRandom(new BigInteger(args[6]).toByteArray());
		else
			r = new SecureRandom();
		int numKeys = Integer.parseInt(args[2]);
		int start = 0;
		Writer arg0 = null;
		BufferedWriter out, out2, out3, out4;
		
		double pOwned = Double.parseDouble(args[3]);
		if(pOwned > 1 || pOwned < 0) throw new Exception("Must be between 0 and 1");
		double pOwnedByP1 = Double.parseDouble(args[4]);
		if(pOwnedByP1 > 1 || pOwnedByP1 < 0) throw new Exception("Must be between 0 and 1");
		
		if(args.length >= 6 && args[5] != null && args[5] != "0" && args[5] != "")
		{
			int last = Integer.parseInt(args[5]);
			if(last <= numKeys)
			{
				Files.copy(new File("DLP1Keys" + args[5] + "_" + args[3] + "_" + args[4]).toPath(), new File("P1Keys" + args[2] + "_" + args[3] + "_" + args[4]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				Files.copy(new File("DLAccount" + args[5] + "_" + args[3] + "_" + args[4]).toPath(), new File("Account" + args[2] + "_" + args[3] + "_" + args[4]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				Files.copy(new File("DLP2Keys" + args[5] + "_" + args[3] + "_" + args[4]).toPath(), new File("P2Keys" + args[2] + "_" + args[3] + "_" + args[4]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				Files.copy(new File("DLKeys" + args[5] + "_" + args[3] + "_" + args[4]).toPath(), new File("Keys" + args[2] + "_" + args[3] + "_" + args[4]).toPath(), StandardCopyOption.REPLACE_EXISTING);
				start = last;
				try {
					arg0 = new FileWriter("DLKeys" + args[2] + "_" + args[3] + "_" + args[4], true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				out = new BufferedWriter(arg0);

				
				try {
					arg0 = new FileWriter("DLAccount" + args[2] + "_" + args[3] + "_" + args[4], true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	
				out2 = new BufferedWriter(arg0);

				
				try {
					arg0 = new FileWriter("DLP1Keys" + args[2] + "_" + args[3] + "_" + args[4], true);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}		
				out3 = new BufferedWriter(arg0);

				
				try {
					arg0 = new FileWriter("DLP2Keys" + args[2] + "_" + args[3] + "_" + args[4], true);
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
				arg0 = new FileWriter("DLKeys" + args[2] + "_" + args[3] + "_" + args[4]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}			
			out = new BufferedWriter(arg0);

			
			try {
				arg0 = new FileWriter("DLAccount" + args[2] + "_" + args[3] + "_" + args[4]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}			
			out2 = new BufferedWriter(arg0);

			
			try {
				arg0 = new FileWriter("DLP1Keys" + args[2] + "_" + args[3] + "_" + args[4]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}	
			out3 = new BufferedWriter(arg0);
			
			try {
				arg0 = new FileWriter("DLP2Keys" + args[2] + "_" + args[3] + "_" + args[4]);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}		
			out4 = new BufferedWriter(arg0);

		}
		
		System.out.println("Generating Keys (" + numKeys + ")");
		BigInteger[][] results = keyMaster(p, g, numKeys - start, r);
		System.out.println("Writing Keys");
		out.write("//Private Key		Public Key\n");
		out2.write("//Account Balance		Public Key\n");
		out3.write("//Private Key		Owned Public Key\n");
		out4.write("//Private Key		Owned Public Key\n");
		for(int i = 0; i < numKeys - start; i++)
		{
			String toWrite0 = Base64.getEncoder().encodeToString(results[i][0].toByteArray());
			String toWrite1 = Base64.getEncoder().encodeToString(results[i][1].toByteArray());
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
		final long endTime = System.currentTimeMillis();
		System.out.println("Time (ms): " + (endTime - startTime));
	}
	public static BigInteger[][] keyMaster(BigInteger p, BigInteger g, int numKeys, Random r)
	{
		BigInteger[][] toReturn = new BigInteger[numKeys][];
		for(int i = 0; i < numKeys; i++)
		{
			
			BigInteger privateKey;
			do {
				privateKey = new BigInteger(p.bitLength(), r);
				if(privateKey.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO))
				{
					privateKey = privateKey.add(BigInteger.ONE);
				}
				if(privateKey.mod(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))).equals(BigInteger.ZERO))
				{
					privateKey = p;
				}
			}while(privateKey.compareTo(p.subtract(BigInteger.ONE)) >= 0);
			
			BigInteger publicKey = g.modPow(privateKey, p);
			
			toReturn[i] = new BigInteger[] {privateKey, publicKey};
		}
		return toReturn;
	}
}

