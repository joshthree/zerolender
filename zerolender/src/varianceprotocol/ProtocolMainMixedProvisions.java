package varianceprotocol;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Writer;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.Date;
import java.util.Random;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.BigIntData;
import zero_knowledge_proofs.DLPedersenCommitment;
import zero_knowledge_proofs.InvalidStringFormatException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ProvisionsProver;
import zero_knowledge_proofs.ProvisionsVerifier;
import zero_knowledge_proofs.ZKPData;
import zero_knowledge_proofs.ZKPDataArray;
import zero_knowledge_proofs.ZKPProverInterface;
import zero_knowledge_proofs.ZKPVerifierInterface;

public class ProtocolMainMixedProvisions {
	//TODO Make usage statement:  <excecutable> <ip> <port> <accounts file name> <key file name> <environment file name> <blockSize> [seed (optional)]
	static boolean otherVerify = true;
	static boolean myVerify = true; //This is lousy, make it an instance
	static DLPedersenCommitment othersSumCommitment;

	@SuppressWarnings({ "resource" })
	public static void main(String[] args) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, SecurityException, InvalidStringFormatException, IOException, ClassNotFoundException{
		int debug = 0;

		Encoder encoder = Base64.getEncoder();
		Decoder decoder = Base64.getDecoder();
		
		System.out.println(new Date());
		
		ZKPProverInterface.registerProtocol("Provisions", ProvisionsProver.class, true);
		ZKPProverInterface prover = ZKPProverInterface.generateProver("Provisions");

		ZKPVerifierInterface.registerProtocol("Provisions", ProvisionsVerifier.class, true);
		ZKPVerifierInterface verifier = ZKPVerifierInterface.generateVerifier("Provisions");

		ServerSocket host = null;
		Socket s;
		ObjectInputStream in;
		ObjectOutputStream out;
		
		InputStream fis = new FileInputStream(args[2]);
	    InputStreamReader isr = new InputStreamReader(fis);
	    BufferedReader br = new BufferedReader(isr);
	    
		InputStream keyFile = new FileInputStream(args[3]);
	    InputStreamReader isr2 = new InputStreamReader(keyFile);
	    BufferedReader keyBr = new BufferedReader(isr2);
	    
		InputStream envFile = new FileInputStream(args[4]);
	    InputStreamReader isr3 = new InputStreamReader(envFile);
	    BufferedReader envBr = new BufferedReader(isr3);

	    int blockSize = Integer.parseInt(args[5]);
	    DLPedersenCommitment[][] otherCommitments = new DLPedersenCommitment[blockSize][2];
		
	    System.out.println("Attempting to Connect");
	    Random r;
	    if(args.length == 7)
	    {
	    	BigInteger seedInt = new BigInteger(args[6]);
	    	byte[] seed = seedInt.toByteArray();
	    	r = new SecureRandom(seed);
	    }
	    else {
	    	r = new SecureRandom();
	    }
		
		try {
			SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
			s = new Socket();
			s.connect(dest);
			System.out.println("Connection to Server successful");
			in = new ObjectInputStream(s.getInputStream());
			out = new ObjectOutputStream(s.getOutputStream());
		}
		catch(Exception e){
			System.out.println("Connection not open, opening server");
			try {
				host = new ServerSocket(Integer.parseInt(args[1]));
				s = host.accept();
				if(args[0].equals(s.getInetAddress().getHostAddress())){
					System.out.println("");
				}
				System.out.println("Connection established");
				out = new ObjectOutputStream(s.getOutputStream());
				in = new ObjectInputStream(s.getInputStream());
			}
			catch( java.net.BindException ex)
			{
				SocketAddress dest = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
				s = new Socket();
				s.connect(dest);
				System.out.println("Connection to Server successful");
				in = new ObjectInputStream(s.getInputStream());
				out = new ObjectOutputStream(s.getOutputStream());
			}
		}
		final long startTime = System.currentTimeMillis();
		
	    
		String dataRow;

		dataRow = envBr.readLine();
		String[] envString = dataRow.split("\t");
		BigInteger g = new BigInteger(envString[0]);
		BigInteger h = new BigInteger(envString[1]);
		BigInteger p = new BigInteger(envString[2]);
		BigInteger orderP = p.subtract(BigInteger.ONE);
		int bitLength = p.bitLength() - 1;//I would like to avoid my random numbers being greater than the prime.	

		
		ArrayList<BigInteger[]> knownKeys = new ArrayList<BigInteger[]>();
		ZKPData environment = new ZKPDataArray(new BigInteger[] {g, p, h});
		ZKPData[] commEnv = environment.getZKPDataArray();
		
		ZKPData[] commitment1Env = new ZKPDataArray(new BigInteger[] {h, p, null}).getZKPDataArray();
		ZKPData[] commitment2Env = new ZKPDataArray(new BigInteger[] {g, p, h}).getZKPDataArray();
		
		BigInteger sum = BigInteger.ZERO;
		BigInteger[] sumKey = new BigInteger[] {BigInteger.ZERO};
		
		othersSumCommitment = new DLPedersenCommitment(BigInteger.ZERO, new BigInteger[] {BigInteger.ZERO}, commitment2Env);
		
		while((dataRow = keyBr.readLine()) != null)
		{
			//String format:  "Public Key	Private Key"
			 
			String[] stringData = dataRow.split("\t");

			if(stringData[0].length() >= 2 && stringData[0].substring(0, 2).equals("//")) {
				if(debug != 0)  System.out.printf("Key Line Omitted:  %s\n", dataRow);
				continue;	//lines can be commented with //
			}
			if(stringData.length != 2) 
			{
				System.err.printf("Line rejected from Keys:  %s\n", dataRow);
				continue;				
			}
			
			
			BigInteger[] keyPair = new BigInteger[2];
			try
			{
				keyPair[0] = new BigInteger(decoder.decode(stringData[0]));
				keyPair[1] = new BigInteger(decoder.decode(stringData[1]));
				knownKeys.add(keyPair);
			}
			catch(Exception e)
			{
				System.err.println("Line failed:  Not parsed as numbers.  " + dataRow);
				continue;
			}
		}
		
		knownKeys.add(new BigInteger[] {BigInteger.ZERO, BigInteger.ZERO});
		int counter = 0;
		int index = 0;
		int proverIndex = 0;
		ZKPData[] input = new ZKPData[blockSize];
		BigInteger[][] acc = new BigInteger[blockSize][3];

		Writer arg0 = null;
		try {
			arg0 = new FileWriter("Verifier_Transcript_" + args[3]);
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		BufferedWriter out2 = new BufferedWriter(arg0);
		StringBuilder transcript = new StringBuilder();

		while((dataRow = br.readLine()) != null)
		{
			
			if(dataRow.length() == 0) continue;
			
			//String Format:  "Amount in account	Public Key" for each line. 
			String[] stringData = dataRow.split("\t");
			
			if(stringData[0].length() >= 2 && stringData[0].substring(0, 2).equals("//")) {
				if(debug != 0)  System.out.printf("Account Line Omitted:  %s\n", dataRow);
				continue;	//lines can be commented with //
			}
			if(stringData.length != 2) 
			{
				System.err.printf("Line rejected from accounts:  %s\n", dataRow);
				continue;				
			}

			counter++;
//			if(counter % 2<<15 == 0)
//			{
//				out.flush();
//				out.reset();
//			}
			try
			{
//				System.out.println("IN TRY:			" + stringData[0] + "     " + stringData[1]);
				acc[proverIndex][0] = new BigInteger(stringData[0]);
				acc[proverIndex][1] = new BigInteger(decoder.decode(stringData[1]));
				acc[proverIndex][2] = g.modPow(acc[proverIndex][0], p);
			}
			catch(Exception e)
			{
				System.err.println("Line failed:  Not parsed as numbers.  " + dataRow);
				continue;
			}
			BigInteger[] k = knownKeys.get(index);
			BigInteger[] commKey = new BigInteger[1];	
			if(k[1].equals(acc[proverIndex][1])){
				index++;
				
				BigInteger[] bIntArray = new BigInteger[13];
				BigInteger v = new BigInteger(bitLength - 1, r);
				BigInteger t = new BigInteger(bitLength - 1, r);
				
				DLPedersenCommitment[] commitments = new DLPedersenCommitment[2];
				
				commKey[0] = v;
				commitment1Env[2] = new BigIntData(acc[proverIndex][2]);
				commitments[0] = new DLPedersenCommitment(BigInteger.ONE, commKey, commitment1Env);

				
				commKey[0] = t;
				commitment1Env[2] = new BigIntData(acc[proverIndex][1]);
				commitments[1] = new DLPedersenCommitment(BigInteger.ONE, commKey, commitment1Env);
				
				sumKey[0] = sumKey[0].add(v).mod(orderP);
				sum = sum.add(acc[proverIndex][0]);
				
				out.writeObject(commitments);

				//[0      , 1         , 2   , 3  , 4  , 5  , 6  , 7  , 8  , 9  , 10 , 11 , 12 ]
				//[account, public key, xhat, v_i, t_i, s_i, u_1, u_2, u_3, u_4, u_5, u_6, c_f]
				bIntArray[0] = acc[proverIndex][2];
				bIntArray[1] = acc[proverIndex][1];
				bIntArray[2] = k[0];
				bIntArray[3] = v;
				bIntArray[4] = t;
				bIntArray[5] = BigInteger.ONE;
				bIntArray[6] = new BigInteger(bitLength - 1, r);
				bIntArray[7] = new BigInteger(bitLength - 1, r);
				bIntArray[8] = new BigInteger(bitLength - 1, r);
				bIntArray[9] = new BigInteger(bitLength - 1, r);
				bIntArray[10] = new BigInteger(bitLength - 1, r);
				bIntArray[11] = new BigInteger(bitLength - 1, r);
				bIntArray[12] = new BigInteger(bitLength - 1, r);
				
				input[proverIndex] = new ZKPDataArray(bIntArray);
			}
			else
			{
				BigInteger[] bIntArray = new BigInteger[13];
				BigInteger v = new BigInteger(bitLength - 1, r);
				BigInteger t = new BigInteger(bitLength - 1, r);
				
				DLPedersenCommitment[] commitments = new DLPedersenCommitment[2];
				
				commKey[0] = v;
				commitment1Env[2] = new BigIntData(acc[proverIndex][2]);
				commitments[0] = new DLPedersenCommitment(BigInteger.ZERO, commKey, commitment1Env);

				
				commKey[0] = t;
				commitment1Env[2] = new BigIntData(acc[proverIndex][1]);
				commitments[1] = new DLPedersenCommitment(BigInteger.ZERO, commKey, commitment1Env);
				
				sumKey[0] = sumKey[0].add(v).mod(orderP);
				
				out.writeObject(commitments);

				//[0      , 1         , 2   , 3  , 4  , 5  , 6  , 7  , 8  , 9  , 10 , 11 , 12 ]
				//[account, public key, xhat, v_i, t_i, s_i, u_1, u_2, u_3, u_4, u_5, u_6, c_f]
				bIntArray[0] = acc[proverIndex][2];
				bIntArray[1] = acc[proverIndex][1];
				bIntArray[2] = BigInteger.ZERO;
				bIntArray[3] = v;
				bIntArray[4] = t;
				bIntArray[5] = BigInteger.ZERO;
				bIntArray[6] = new BigInteger(bitLength - 1, r);
				bIntArray[7] = new BigInteger(bitLength - 1, r);
				bIntArray[8] = new BigInteger(bitLength - 1, r);
				bIntArray[9] = new BigInteger(bitLength - 1, r);
				bIntArray[10] = new BigInteger(bitLength - 1, r);
				bIntArray[11] = new BigInteger(bitLength - 1, r);
				bIntArray[12] = new BigInteger(bitLength - 1, r);
				
				input[proverIndex] = new ZKPDataArray(bIntArray);
			}
			proverIndex++;
			if(proverIndex == blockSize)
			{
				runProver(prover, verifier, host, in, out, otherCommitments, r, h, p, bitLength, commitment2Env,
						environment, proverIndex, acc, input, transcript);
				out2.write(transcript.toString());
				transcript.setLength(0);
				out2.flush();
				out.flush();
				out.reset();
				proverIndex = 0;
			}

		}
		if(proverIndex != 0)
		{
			runProver(prover, verifier, host, in, out, otherCommitments, r, h, p, bitLength, commitment2Env,
					environment, proverIndex, acc, input, transcript);
			out2.write(transcript.toString());
			transcript.setLength(0);
			out2.flush();
		}


		

		if(myVerify && otherVerify)
			System.out.println("Success!");
		else 
		{
			if(!myVerify)
				System.out.println("He does not believe me");
			if(!otherVerify)
				System.out.println("I don't believe him");
		}
		out.flush();
		out2.flush();
		out2.close();
		final long endTime = System.currentTimeMillis();
		System.out.println(counter);
		out.writeObject(sum);
		out.writeObject(sumKey);
		BigInteger otherSum = (BigInteger) in.readObject();
		BigInteger[] otherKeySum = (BigInteger[]) in.readObject();
		out.flush();
		commitment1Env[2] = new BigIntData(g);
		if(othersSumCommitment.verifyCommitment(otherSum, otherKeySum, commitment1Env))
		{
			System.out.println("Good Sum:  He owns " + sum + " Bitcoin");
		}
		else 
		{
			
			System.out.printf("LIAR:\n\tC = %s\n\tm = %s\n\tr = %s\n\t\n", othersSumCommitment.getCommitment(), otherSum, otherKeySum[0]);
		}

		System.out.println("Total execution time: " + (endTime - startTime) );
		try {
			arg0 = new FileWriter("ProvisionsOutput_" + args[3]);
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		BufferedWriter out1 = new BufferedWriter(arg0);

		if(myVerify && otherVerify)
			out1.write("Success!\n");
		else 
		{
			if(!myVerify)
				out1.write("He does not believe me\n");
			if(!otherVerify)
				out1.write("I don't believe him\n");
		}
		out1.write(String.format("Total execution time: %d\n", (endTime - startTime)));
		out1.flush();
		out.close();
		out1.close();
		in.close();
		s.close();
		if(host != null) host.close();
	}

	private static void runProver(ZKPProverInterface prover, ZKPVerifierInterface verifier, ServerSocket host,
			ObjectInputStream in, ObjectOutputStream out, DLPedersenCommitment[][] otherCommitments, Random r, BigInteger h,
			BigInteger p, int bitLength, ZKPData[] commitmentEnv, ZKPData environment, int proverIndex,
			BigInteger[][] acc, ZKPData[] input, StringBuilder transcript) throws IOException {
		
		for(int i = 0; i < proverIndex; i++)
		{
			try { 
				otherCommitments[i] = (DLPedersenCommitment[]) in.readObject();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
		}
		out.flush();
		for(int i = 0; i < proverIndex; i++)
		{					
			
			ZKPData otherInput = new ZKPDataArray(new BigInteger[] {acc[i][2], acc[i][1], otherCommitments[i][0].getCommitment(), otherCommitments[i][1].getCommitment()});
			
			try {
				if(host == null) {
					myVerify = prover.prove(input[i], environment, in, out);
					otherVerify = verifier.verify(otherInput, new BigInteger(bitLength, r), environment, in, out, transcript);
					if(!(myVerify && otherVerify)) {
//							System.out.println(myVerify + " " + otherVerify);
						break;
					}
					else othersSumCommitment = othersSumCommitment.multiplyCommitment(otherCommitments[i][0], commitmentEnv);
					
				}
				else {
					otherVerify = verifier.verify(otherInput, new BigInteger(bitLength, r), environment, in, out, transcript);
					myVerify = prover.prove(input[i], environment, in, out);
					if(!(myVerify && otherVerify))
					{
//							System.out.println(myVerify + " " + otherVerify);
						break;
					}
					else othersSumCommitment = othersSumCommitment.multiplyCommitment(otherCommitments[i][0], commitmentEnv);
				
				}
			} catch (ClassNotFoundException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e) {
				
				e.printStackTrace();
			}
		}
	}

}
