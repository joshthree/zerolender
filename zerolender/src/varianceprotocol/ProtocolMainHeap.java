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
import java.util.Random;

import commitment.DLPedersenCommitment;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.InvalidStringFormatException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.DLSchnorrProver;
import zero_knowledge_proofs.DLSchnorrVerifier;
import zero_knowledge_proofs.ZKPData;
import zero_knowledge_proofs.ZKPDataArray;
import zero_knowledge_proofs.ZKPProverInterface;
import zero_knowledge_proofs.ZKPVerifierInterface;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeAndVerifier;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.ZeroKnowledgeOrVerifier;

public class ProtocolMainHeap {
	//TODO Make usage statement:  <excecutable> <ip> <port> <accounts file name> <key file name> <environment file name> [seed (optional)]
	@SuppressWarnings({ "resource", "unchecked" })
	public static void main(String[] args) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, SecurityException, InvalidStringFormatException, IOException, ClassNotFoundException{
		int debug = 0;

		System.out.println(new File("").getAbsolutePath());
		
		boolean myVerify = true;
		boolean otherVerify = true;
		
		ZKPProverInterface.registerProtocol("Schnorr", DLSchnorrProver.class, false);
		ZKPProverInterface.registerProtocol("AND", ZeroKnowledgeAndProver.class, true);
		ZKPProverInterface.registerProtocol("OR", ZeroKnowledgeOrProver.class, true);
		ZKPProverInterface prover = ZKPProverInterface.generateProver("OR(AND(Schnorr,Schnorr),Schnorr)");

		ZKPVerifierInterface.registerProtocol("Schnorr", DLSchnorrVerifier.class, false);
		ZKPVerifierInterface.registerProtocol("AND", ZeroKnowledgeAndVerifier.class, true);
		ZKPVerifierInterface.registerProtocol("OR", ZeroKnowledgeOrVerifier.class, true);
		ZKPVerifierInterface verifier = ZKPVerifierInterface.generateVerifier("OR(AND(Schnorr,Schnorr),Schnorr)");

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
	    
	    System.out.println("Attempting to Connect");
	    Random r;
	    if(args.length == 6)
	    {
	    	BigInteger seedInt = new BigInteger(args[5]);
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
			host = new ServerSocket(Integer.parseInt(args[1]));
			s = host.accept();
			if(args[0].equals(s.getInetAddress().getHostAddress())){
				System.out.println("");
			}
			System.out.println("Connection established");
			out = new ObjectOutputStream(s.getOutputStream());
			in = new ObjectInputStream(s.getInputStream());
		}
		

		final long startTime = System.currentTimeMillis();
		String dataRow;
	    ArrayList<BigInteger[]> knownKeys = new ArrayList<BigInteger[]>();
	    ArrayList<BigInteger[]> accounts = new ArrayList<BigInteger[]>();
	    ArrayList<DLPedersenCommitment> myCommitments = new ArrayList<DLPedersenCommitment>();
	    ArrayList<DLPedersenCommitment> otherCommitments = new ArrayList<DLPedersenCommitment>();
	    ArrayList<ZKPData> zkpProverData = new ArrayList<ZKPData>();
	    ArrayList<ZKPData> zkpVerifierData = new ArrayList<ZKPData>();
	    
	    dataRow = envBr.readLine();

		String[] envString = dataRow.split("\t");
		BigInteger g = new BigInteger(envString[0]);
		BigInteger h = new BigInteger(envString[1]);
		BigInteger p = new BigInteger(envString[2]);
	    
		int bitLength = p.bitLength() - 1;//I would like to avoid my random numbers being greater than the prime.	

		ZKPData miniEnv = new ZKPDataArray(new BigInteger[] {g, p, h});
		
		BigInteger[] commitmentEnv = new BigInteger[] {h, g, p};
		
		DLPedersenCommitment othersSumCommitment = new DLPedersenCommitment(BigInteger.ZERO, new BigInteger[] {BigInteger.ZERO}, commitmentEnv);
		BigInteger sum = BigInteger.ZERO;
		BigInteger[] sumKey = new BigInteger[] {BigInteger.ZERO};
		
		ZKPData environment = new ZKPDataArray(new ZKPData[] {new ZKPDataArray (new ZKPData[] {miniEnv, miniEnv}), miniEnv});
		
		
		while((dataRow = keyBr.readLine()) != null)
		{
			//String format:  "Public Key	Private Key"
			if(dataRow.length() == 0) continue;
			String[] stringData = dataRow.split("\t");
			
			
			if(stringData[0].length() >= 2 && stringData[0].substring(0, 2).equals("//")) {
				if(debug != 0)  System.out.printf("Line Omitted:  %s\n", dataRow);
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
				keyPair[0] = new BigInteger(stringData[0]);
				keyPair[1] = new BigInteger(stringData[1]);
				knownKeys.add(keyPair);
			}
			catch(Exception e)
			{
				System.err.println("Line failed:  Not parsed as numbers.  " + dataRow);
				continue;
			}
		}
		

		
		
		while((dataRow = br.readLine()) != null)
		{
			//String Format:  "Amount in account	Public Key" for each line. 
			if(dataRow.length() == 0) continue;
			String[] stringData = dataRow.split("\t");
			
			
			if(stringData[0].length() >= 2 && stringData[0].substring(0, 2).equals("//")) {
				if(debug != 0)  System.out.printf("Line Omitted:  %s\n", dataRow);
				continue;	//lines can be commented with //
			}
			if(stringData.length != 2) 
			{
				System.err.printf("Line rejected from accounts:  %s\n", dataRow);
				continue;				
			}

			
			BigInteger[] account = new BigInteger[2];

			try
			{
				account[0] = new BigInteger(stringData[0]);
				account[1] = new BigInteger(stringData[1]);
				accounts.add(account);
			}
			catch(Exception e)
			{
				System.err.println("Line failed:  Not parsed as numbers.  " + dataRow);
				continue;
			}
			
			boolean keyKnown = false;
			for(int i = 0; i < knownKeys.size(); i++)
			{
				BigInteger[] k = knownKeys.get(i);
				
				if(k[1].equals(account[1])){
					knownKeys.remove(k);
					keyKnown = true;
					
					ZKPData[] dataArrayInner = new ZKPData[2];
					ZKPData[] dataArrayOuter = new ZKPData[3];
					BigInteger[] bIntArray = new BigInteger[3];
					bIntArray[0] = k[0];
					bIntArray[1] = k[1];
					bIntArray[2] = new BigInteger(bitLength - 1, r);
					
					dataArrayInner[0] = new ZKPDataArray(bIntArray);
					
					bIntArray = new BigInteger[3];
					BigInteger pcKey = new BigInteger(bitLength - 1, r);
					
					
					//System.out.printf("new PedersenCommitment(%s, [%s], [%s,%s,%s]);\n", account[0], pcKey, commitmentEnv[0], commitmentEnv[1], commitmentEnv[2]);
					DLPedersenCommitment commitment = new DLPedersenCommitment(account[0], new BigInteger[] {pcKey}, commitmentEnv);
					
					sumKey[0] = sumKey[0].add(pcKey);
					sum = sum.add(account[0]);
					
					//System.out.println("Adding true commitment:  " + commitment.getCommitment());
					myCommitments.add(commitment);
					
					bIntArray[0] = pcKey;
					bIntArray[1] = commitment.getCommitment().multiply(h.modPow(account[0].negate(), p)).mod(p);
					bIntArray[2] = new BigInteger(bitLength - 1, r);
				

					dataArrayInner[1] = new ZKPDataArray(bIntArray);
					dataArrayOuter[0] = new ZKPDataArray(dataArrayInner);
					
					bIntArray = new BigInteger[2];
					bIntArray[0] = commitment.getCommitment();
					bIntArray[1] = new BigInteger(bitLength - 1, r);
					
					dataArrayOuter[1] = new ZKPDataArray(bIntArray);
					
					BigInteger[] challenges = new BigInteger[2];
					challenges[0] = BigInteger.ZERO;
					do {
						challenges[1] = new BigInteger(bitLength - 1, r);
					}while(challenges[1].equals(BigInteger.ZERO));
					
					dataArrayOuter[2] = new ZKPDataArray(challenges);
					zkpProverData.add(new ZKPDataArray(dataArrayOuter));
					
					break;
				}
			}
			if(keyKnown == false)
			{
				BigInteger pcKey = new BigInteger(bitLength - 1, r);
				
				sumKey[0] = sumKey[0].add(pcKey);
				
				DLPedersenCommitment commitment = new DLPedersenCommitment(BigInteger.ZERO, new BigInteger[] {pcKey}, commitmentEnv);
				
				//System.out.println("Adding fake commitment:  " + commitment.getCommitment());
				myCommitments.add(commitment);
				
				BigInteger[] bIntArray = new BigInteger[3];
				
				ZKPData[] dataArrayInner = new ZKPData[2];
				ZKPData[] dataArrayOuter = new ZKPData[3];
				
				bIntArray[0] = pcKey;
				bIntArray[1] = commitment.getCommitment();
				bIntArray[2] = new BigInteger(bitLength - 1, r);
				
				dataArrayOuter[1] = new ZKPDataArray(bIntArray);
				
				bIntArray = new BigInteger[2];
				
				bIntArray[0] = account[1];
				bIntArray[1] = new BigInteger(bitLength - 1, r);
				
				dataArrayInner[0] = new ZKPDataArray(bIntArray);
				
				bIntArray = new BigInteger[2];

				bIntArray[0] = commitment.getCommitment().multiply(h.modPow(account[0].negate(), p)).mod(p);
				bIntArray[1] = new BigInteger(bitLength - 1, r);
				
				dataArrayInner[1] = new ZKPDataArray(bIntArray);
				
				dataArrayOuter[0] = new ZKPDataArray(dataArrayInner);
				
				BigInteger[] challenges = new BigInteger[2];
				do {
					challenges[0] = new BigInteger(bitLength - 1, r);
				}while(challenges[0].equals(BigInteger.ZERO));
				challenges[1] = BigInteger.ZERO;
				dataArrayOuter[2] = new ZKPDataArray(challenges);
				
				zkpProverData.add(new ZKPDataArray(dataArrayOuter));
			}
		}
		//System.out.println("Commitments list size = " + myCommitments.size());
		out.writeObject(myCommitments);
		try {
			otherCommitments = (ArrayList<DLPedersenCommitment>) in.readObject();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		
		for(int i = 0; i < accounts.size(); i++)
		{
			BigInteger[] a = accounts.get(i);
			//System.out.printf("Making Verifier ZKPData:\n\ti = %d\n\ta[0] = %s\n\ta[1] = %s\n", i, a[0], a[1]);
			BigInteger comm = otherCommitments.get(i).getCommitment();

			
			ZKPData[] dataArrayInner = new ZKPData[2];
			ZKPData[] dataArrayOuter = new ZKPData[2];
			
			BigInteger[] bIntArray = new BigInteger[1];
			bIntArray[0] = a[1];
			
			dataArrayInner[0] = new ZKPDataArray(bIntArray);

			bIntArray = new BigInteger[1];
			bIntArray[0] = comm.multiply(h.modPow(a[0].negate(), p)).mod(p);
			
			dataArrayInner[1] = new ZKPDataArray(bIntArray);

			dataArrayOuter[0] = new ZKPDataArray(dataArrayInner);
			
			bIntArray = new BigInteger[1];
			bIntArray[0] = comm;
			
			dataArrayOuter[1] = new ZKPDataArray(bIntArray);
			
			zkpVerifierData.add(new ZKPDataArray(dataArrayOuter));
		}
		
		try {
			otherVerify = true;
			myVerify = true;
			if(host == null) {
				for(int i = 0; i < accounts.size(); i++) {
					myVerify = prover.prove(zkpProverData.get(i), environment, in, out);
					otherVerify = verifier.verify(zkpVerifierData.get(i), new BigInteger(bitLength - 1, r), environment, in, out);
					if(!(myVerify && otherVerify)) {
//						System.out.println(myVerify + " " + otherVerify);
						break;
					}
					else othersSumCommitment = othersSumCommitment.multiplyCommitment(otherCommitments.get(i), commitmentEnv);
				}
			}
			else {
				for(int i = 0; i < accounts.size(); i++) {
					otherVerify = verifier.verify(zkpVerifierData.get(i), new BigInteger(bitLength - 1, r), environment, in, out);
					myVerify = prover.prove(zkpProverData.get(i), environment, in, out);
					if(!(myVerify && otherVerify))
					{
//						System.out.println(myVerify + " " + otherVerify);
						break;
					}
					else othersSumCommitment = othersSumCommitment.multiplyCommitment(otherCommitments.get(i), commitmentEnv);

				}
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
		} catch (ClassNotFoundException | MultipleTrueProofException | NoTrueProofException
				| ArraySizesDoNotMatchException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		out.writeObject(sum);
		out.writeObject(sumKey);
		BigInteger otherSum = (BigInteger) in.readObject();
		BigInteger[] otherKeySum = (BigInteger[]) in.readObject();

		if(othersSumCommitment.verifyCommitment(otherSum, otherKeySum, commitmentEnv))
		{
			System.out.println("Good Sum:  He owns " + sum + " Bitcoin");
		}
		else 
		{
			
			System.out.printf("LIAR:\n\tC = %s\n\tm = %s\n\tr = %s\n\t\n", othersSumCommitment.getCommitment(), otherSum, otherKeySum[0]);
		}
		
		out.flush();
		final long endTime = System.currentTimeMillis();
		Writer arg0 = null;
		try {
			arg0 = new FileWriter(args[3] + "Output");
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
		System.out.printf("Total execution time: %d\n", (endTime - startTime));
		out1.flush();
	}

}
