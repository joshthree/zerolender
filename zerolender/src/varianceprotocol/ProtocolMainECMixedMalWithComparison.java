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
import java.util.Date;
import java.util.InputMismatchException;
import java.util.Random;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.util.Base64.Decoder;

import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.CheaterException;
import zero_knowledge_proofs.InvalidStringFormatException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.VarianceToolkit;
import zero_knowledge_proofs.ECPedersenCommitment;
import zero_knowledge_proofs.ECPedersenOwnedBitwiseCommitment;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class ProtocolMainECMixedMalWithComparison {
	//TODO Make usage statement:  <excecutable> <ip> <port> <accounts file name> <key file name> <environment file name> <blockSize> [seed (optional)]

	static boolean verify = true; //This is lousy, make it an instance
	static ECPedersenCommitment othersSumCommitment;

	@SuppressWarnings({ "resource" })
	public static void main(String[] args) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, SecurityException, InvalidStringFormatException, IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException{
		int debug = 1;

		Decoder decoder = Base64.getDecoder();
		System.out.println(new Date());
		System.out.println(new File("").getAbsolutePath());
		VarianceToolkit.register();
		ZKPProtocol prover = ZKPProtocol.generateProver("OR(AND(ECSchnorr,ECSchnorr),ECSchnorr)");

		ServerSocket host = null;
		Socket s;
		ObjectInputStream in;
		ObjectOutputStream out;

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
	   ECPedersenCommitment[] otherCommitments = new ECPedersenCommitment[blockSize];
		
	    System.out.println("Attempting to Connect");
	    SecureRandom r;
	    if(args.length == 7)
	    {
	    	BigInteger seedInt = new BigInteger(args[6]);
	    	byte[] seed = seedInt.toByteArray();
	    	r = new SecureRandom(seed);
	    }
	    else {
	    	r = new SecureRandom();
	    }
		
		
	    
		String dataRow;

		dataRow = envBr.readLine();
		String[] envString = dataRow.split("\t");
		ECPoint g = ECNamedCurveTable.getParameterSpec(envString[0]).getG();
		ECCurve curve = g.getCurve();
		BigInteger order = g.getCurve().getOrder();
		int bitLength = order.bitLength();

		BigInteger myPartOfKey = new BigInteger(bitLength, r);
		while(myPartOfKey.compareTo(order) >= 0)
		{
			myPartOfKey = new BigInteger(bitLength, r);
		}
		ECPoint halfH = g.multiply(myPartOfKey);
		out.writeObject(halfH.getEncoded(true));
		ECPoint otherHalfH = curve.decodePoint((byte[]) in.readObject());
		
		ECPoint h = halfH.add(otherHalfH);
		
		ArrayList<CryptoData[]> knownKeys = new ArrayList<CryptoData[]>();
		CryptoData miniEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g), new ECPointData(h)});
		
		CryptoData revMiniEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, h), new ECPointData(g)});
		
		
		BigInteger sum = BigInteger.ZERO;
		BigInteger sumKey = BigInteger.ZERO;
		
		CryptoData environment = new CryptoDataArray(new CryptoData[] {new CryptoDataArray (new CryptoData[] {miniEnv, revMiniEnv}), revMiniEnv});

		othersSumCommitment = new ECPedersenCommitment(BigInteger.ZERO, BigInteger.ZERO, miniEnv);

		Writer arg0 = null;
		try {
			arg0 = new FileWriter("Verifier_Transcript_" + args[3] + "_Variance");
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		BufferedWriter out2 = new BufferedWriter(arg0);
		StringBuilder transcript = new StringBuilder();
		transcript.append("Environment:  ");
		transcript.append(environment.toString64());
		transcript.append("\n\n");
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
			
			
			CryptoData[] keyPair = new CryptoData[2];
			try
			{
				keyPair[0] = new BigIntData(new BigInteger(decoder.decode(stringData[0])));
				keyPair[1] = new ECPointData(curve.decodePoint(decoder.decode(stringData[1])));
				knownKeys.add(keyPair);
			}
			catch(Exception e)
			{
				System.err.println("Line failed:  Not parsed as numbers.  " + dataRow);
				continue;
			}
		}
		
		knownKeys.add(new CryptoData[] {new BigIntData(BigInteger.ZERO), new ECPointData(g)});
		int counter = 0;
		int index = 0;
		int proverIndex = 0;
		CryptoData[] input = new CryptoData[blockSize];
		CryptoData[][] acc = new CryptoData[blockSize][2];

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
				acc[proverIndex][0] = new BigIntData(new BigInteger(stringData[0], 16));
				acc[proverIndex][1] = new ECPointData(curve.decodePoint(decoder.decode(stringData[1])));
			}
			catch(Exception e)
			{
				System.err.println("Line failed:  Not parsed as numbers.  " + dataRow);
				continue;
			}
			CryptoData[] k = knownKeys.get(index);
			BigInteger random;
			if(k[1].getECPointData(curve).equals(acc[proverIndex][1].getECPointData(curve))){
				index++;
				
				CryptoData[] dataArrayInner = new CryptoData[2];
				CryptoData[] dataArrayOuter = new CryptoData[3];
				CryptoData[] bIntArray = new CryptoData[3];
				bIntArray[0] = k[1];
				random = new BigInteger(bitLength, r);
				while(random.compareTo(order) >= 0)
					random = new BigInteger(bitLength, r);
				
				bIntArray[1] = new BigIntData(random);
				bIntArray[2] = k[0];
				
				dataArrayInner[0] = new CryptoDataArray(bIntArray);
				
				bIntArray = new CryptoData[3];
				random = new BigInteger(bitLength, r);
				while(random.compareTo(order) >= 0)
					random = new BigInteger(bitLength, r);
				BigInteger pcKey = random;
				
				
				ECPedersenCommitment commitment = new ECPedersenCommitment(acc[proverIndex][0].getBigInt(), pcKey, miniEnv);
		   		
				sumKey = sumKey.add(pcKey).mod(order);
				sum = sum.add(acc[proverIndex][0].getBigInt()).mod(order);
				
				//System.out.println("Sending true commitment:  " + commitment.getCommitment());
				out.writeObject(commitment);

				bIntArray[0] = new ECPointData(commitment.getCommitment(miniEnv).add(g.multiply(acc[proverIndex][0].getBigInt().negate())));

				random = new BigInteger(bitLength, r);
				while(random.compareTo(order) >= 0)
					random = new BigInteger(bitLength, r);
				bIntArray[1] = new BigIntData(random);
				bIntArray[2] = new BigIntData(pcKey);
			

				dataArrayInner[1] = new CryptoDataArray(bIntArray);
				dataArrayOuter[0] = new CryptoDataArray(dataArrayInner);
				
				bIntArray = new CryptoData[2];
				bIntArray[0] = new ECPointData(commitment.getCommitment(miniEnv));
				random = new BigInteger(bitLength, r);
				while(random.compareTo(order) >= 0)
					random = new BigInteger(bitLength, r);
				bIntArray[1] = new BigIntData(random);
				
				dataArrayOuter[1] = new CryptoDataArray(bIntArray);
				
				BigInteger[] challenges = new BigInteger[2];
				challenges[0] = BigInteger.ZERO;
				do {
					challenges[1] = new BigInteger(bitLength - 1, r);
				}while(challenges[1].equals(BigInteger.ZERO));
				
				dataArrayOuter[2] = new CryptoDataArray(challenges);
				input[proverIndex] = new CryptoDataArray(dataArrayOuter);
			}
			else
			{
				BigInteger pcKey = new BigInteger(bitLength, r);
				
				sumKey = sumKey.add(pcKey).mod(order);
				
				ECPedersenCommitment commitment = new ECPedersenCommitment(BigInteger.ZERO, pcKey, miniEnv);
				
				//System.out.println("Sending fake commitment:  " + commitment.getCommitment());
				out.writeObject(commitment);
				CryptoData[] bIntArray = new CryptoData[3];
				
				CryptoData[] dataArrayInner = new CryptoData[2];
				CryptoData[] dataArrayOuter = new CryptoData[3];
				
				bIntArray[0] = new ECPointData(commitment.getCommitment(miniEnv));
				random = new BigInteger(bitLength, r);
				while(random.compareTo(order) >= 0)
					random = new BigInteger(bitLength, r);
				bIntArray[1] = new BigIntData(random);
				bIntArray[2] = new BigIntData(pcKey);
				
				dataArrayOuter[1] = new CryptoDataArray(bIntArray);
				
				bIntArray = new CryptoData[2];
				
				bIntArray[0] = acc[proverIndex][1];
				random = new BigInteger(bitLength, r);
				while(random.compareTo(order) >= 0)
					random = new BigInteger(bitLength, r);
				bIntArray[1] = new BigIntData(random);
				
				dataArrayInner[0] = new CryptoDataArray(bIntArray);
				
				bIntArray = new CryptoData[2];

				bIntArray[0] = new ECPointData(commitment.getCommitment(miniEnv).add(g.multiply(acc[proverIndex][0].getBigInt().negate())));
				random = new BigInteger(bitLength, r);
				while(random.compareTo(order) >= 0)
					random = new BigInteger(bitLength, r);
				bIntArray[1] = new BigIntData(random);
				
				dataArrayInner[1] = new CryptoDataArray(bIntArray);
				
				dataArrayOuter[0] = new CryptoDataArray(dataArrayInner);
				
				BigInteger[] challenges = new BigInteger[2];
				do {
					challenges[0] = new BigInteger(bitLength - 1, r);
				}while(challenges[0].equals(BigInteger.ZERO));
				challenges[1] = BigInteger.ZERO;
				dataArrayOuter[2] = new CryptoDataArray(challenges);

				input[proverIndex] = new CryptoDataArray(dataArrayOuter);
			}
			proverIndex++;
			if(proverIndex == blockSize)
			{
				runProver(prover, host, in, out, otherCommitments, r, g, bitLength, miniEnv, revMiniEnv,
						environment, proverIndex, acc, input, transcript);
				out2.write(transcript.toString());
				transcript.setLength(0);
				out.flush();
				out.reset();
				proverIndex = 0;
			}
		}
		if(proverIndex != 0)
		{
			runProver(prover, host, in, out, otherCommitments, r, g, bitLength, miniEnv, revMiniEnv,
					environment, proverIndex, acc, input, transcript);
			out2.write(transcript.toString());
			transcript.setLength(0);
		}


		

		if(verify)
			System.out.println("Success!  I believe the proof of assets");
		else 
		{
			System.out.println("FAIL");
		}

		out.flush();
		final long endTime = System.currentTimeMillis();
		
//		Debugging stuff:  Opens the commitment to see if the protocol executed correctly
//		out.writeObject(sum);
//		out.writeObject(sumKey);
//		BigInteger otherSum = (BigInteger) in.readObject();
//		BigInteger otherKeySum = (BigInteger) in.readObject();
		//Convert to Bits:

		
		ECPedersenOwnedBitwiseCommitment ecBits = null;
		try {
			ecBits = VarianceToolkit.ECConvertToBits(sum, sumKey, 20, miniEnv, r);
		} catch (InputMismatchException e1) {
			e1.printStackTrace();
		}

		ECPedersenCommitment[] otherECBits = null;

		ECPedersenCommitment[] ecBitComm = ecBits.getComm();
		BigInteger[] ecBitKeys = ecBits.getKeys();
		
		out.writeObject(ecBitComm);
		otherECBits = (ECPedersenCommitment[]) in.readObject();
		
		if(!VarianceToolkit.checkBitCommitment(othersSumCommitment, otherECBits, miniEnv)) System.out.println("LIAR!!! BIT COMMITMENTS DO NOT MATCH THEIR SUM");
		else System.out.println("Bit Commitments Correct");
		CryptoData[][] table = VarianceToolkit.getBasicTable(miniEnv);
		CryptoData[][] newTable;
		
		BigInteger[] keys = new BigInteger[4];
		CryptoData tableProofEnv = VarianceToolkit.getTableProofEnvironment(miniEnv);
		CryptoData shuffleProofEnv = VarianceToolkit.getShuffleProofEnvironment(miniEnv);

		for(int j = 0; j < 4; j++)
		{
			keys[j] = new BigInteger(bitLength, r);
			while(keys[j].compareTo(order) >= 0)
				keys[j] = new BigInteger(bitLength, r);
		}
		
		CryptoData[] encryptions = VarianceToolkit.createTableCommitments(table[1], keys, ecBits.getMessage().testBit(19 - 0), host == null, miniEnv);
		CryptoData pInputs = VarianceToolkit.getTableCoorespondenceProverData(table[1], encryptions, keys, new ECPointData(ecBitComm[19 - 0].getCommitment(miniEnv)), ecBitKeys[19 - 0], ecBits.getMessage().testBit(19 - 0), host != null, miniEnv, r);
		out.writeObject(encryptions);
		CryptoData[] otherEncryptions = (CryptoData[]) in.readObject();
		CryptoData vInputs = VarianceToolkit.getTableCoorespondenceVerifierData(table[1], otherEncryptions, new ECPointData(otherECBits[19 - 0].getCommitment(miniEnv)), host == null, miniEnv);

		BigInteger random;
		random = new BigInteger(bitLength, r);
		while(random.compareTo(order) >= 0)
		{
			random = new BigInteger(bitLength, r);
		}
		BigInteger[] c = {new BigInteger(bitLength - 1, r), random};
		ECPedersenCommitment myCmt = new ECPedersenCommitment(c[0], c[1], miniEnv);
		ObjectInputStream[] inArray = {in}; 
		ObjectOutputStream[] outArray = {out}; 
		if(VarianceToolkit.consistantTableEncryptionProver.parallelZKProve(pInputs, vInputs, tableProofEnv, in, out, myCmt, miniEnv, c, null))
		{
		}
		else System.out.println("boooooo...");
		ECPoint[] feedback = new ECPoint[2];
		int[] shuffle = new int[3];
		BigInteger[][] keyChanges = new BigInteger[3][5];
		
		ECPoint inf = curve.getInfinity();
		for(int i = 1; i < 20; i++)
		{
			feedback[0] = inf;
			feedback[1] = inf;
			for(int j = 0; j < 4; j++)
			{
				CryptoData[] temp = encryptions[j].getCryptoDataArray();
				feedback[0] = feedback[0].add(temp[0].getECPointData(curve));
				feedback[1] = feedback[1].add(temp[1].getECPointData(curve));
				temp = otherEncryptions[j].getCryptoDataArray();
				feedback[0] = feedback[0].add(temp[0].getECPointData(curve));
				feedback[1] = feedback[1].add(temp[1].getECPointData(curve));
			}
			for(int j = 0; j < 3; j++)
			{
				for(int k = 0; k < 5; k++)
				{
					keyChanges[j][k] = new BigInteger(bitLength, r);
					while(keyChanges[j][k].compareTo(order) >= 0)
						keyChanges[j][k] = new BigInteger(bitLength, r);
				}
			}
			shuffle[0] = shuffle[1] = shuffle[2] = 0;
			shuffle[r.nextInt(3)] = 2;
			int pos = r.nextInt(2);
			if(shuffle[pos] != 0)
				shuffle[2] = 1;
			else
				shuffle[pos] = 1;
			CryptoData[][] finalTable;
			CryptoData shufflePInputs;
			CryptoData shuffleVInputs;
			if(host == null)
			{
				newTable = VarianceToolkit.shuffleTable(table, keyChanges, shuffle, miniEnv);
				out.writeObject(newTable);
				shufflePInputs = VarianceToolkit.createZeroKnowledgeProverInputsForShuffle(table, newTable, keyChanges, shuffle, miniEnv, r);
				finalTable = (CryptoData[][]) in.readObject();
				
				shuffleVInputs = VarianceToolkit.createZeroKnowledgeVerifierInputsForShuffle(newTable, finalTable, miniEnv);
			}
			else
			{
				newTable = (CryptoData[][]) in.readObject();
				finalTable = VarianceToolkit.shuffleTable(newTable, keyChanges, shuffle, miniEnv);
				out.writeObject(finalTable);
				shufflePInputs = VarianceToolkit.createZeroKnowledgeProverInputsForShuffle(newTable, finalTable, keyChanges, shuffle, miniEnv, r);
				
				shuffleVInputs = VarianceToolkit.createZeroKnowledgeVerifierInputsForShuffle(table, newTable, miniEnv);
			}
			random = new BigInteger(bitLength, r);
			while(random.compareTo(order) >= 0)
			{
				random = new BigInteger(bitLength, r);
			}
			c[0] = new BigInteger(bitLength - 1, r);
			c[1] = random;
			myCmt = new ECPedersenCommitment(c[0], c[1], miniEnv);

			if(!VarianceToolkit.tableEqualityProver.parallelZKProve(shufflePInputs, shuffleVInputs, shuffleProofEnv, in, out, myCmt, miniEnv, c, null))
			{
				System.out.println("CHEATING SHUFFLE");
			}
			for(int j = 0; j < 4; j++)
			{
				keys[j] = new BigInteger(bitLength, r);
				while(keys[j].compareTo(order) >= 0)
					keys[j] = new BigInteger(bitLength, r);
			}
			
			encryptions = VarianceToolkit.createTableCommitments(table[1], keys, ecBits.getMessage().testBit(19 - i), host == null, miniEnv);
			pInputs = VarianceToolkit.getTableCoorespondenceProverData(table[1], encryptions, keys, new ECPointData(ecBitComm[19 - i].getCommitment(miniEnv)), ecBitKeys[19 - i], ecBits.getMessage().testBit(19 - i), host != null, miniEnv, r);
			out.writeObject(encryptions);
			otherEncryptions = (CryptoData[]) in.readObject();
			vInputs = VarianceToolkit.getTableCoorespondenceVerifierData(table[1], otherEncryptions, new ECPointData(otherECBits[19 - i].getCommitment(miniEnv)), host == null, miniEnv);

			random = new BigInteger(bitLength, r);
			while(random.compareTo(order) >= 0)
			{
				random = new BigInteger(bitLength, r);
			}
			c[0] = new BigInteger(bitLength - 1, r);
			c[1] = random;
			myCmt = new ECPedersenCommitment(c[0], c[1], miniEnv);
			VarianceToolkit.consistantTableEncryptionProver.parallelZKProve(pInputs, vInputs, tableProofEnv, in, out, myCmt, miniEnv, c, null);
			//tables are shuffles and proven to be equal!  Now, PET.
			int row = 0;
			for(;row < 3;row++)
			{
				int x = 0;
				if(host == null)
				{
					x = 1;
				}
				try {
					if(ZKToolkit.plaintextEqualityTest(table[row][0].getCryptoDataArray(), new CryptoDataArray(feedback).getCryptoDataArray(), myPartOfKey, inArray, outArray, miniEnv, -1 + x, 0 - x, r))
					{
						break;
					}
					
					
				} catch (CheaterException e) {
					System.out.println("CHEATER");
					e.printStackTrace();
					System.exit(0);
				}
			}
			if(row == 3) System.out.println("ALL IS LOST!!  THE END IS NEAR!!!");
			for(int j = 0; j < 4; j++)
			{
				keys[j] = new BigInteger(bitLength, r);
				while(keys[j].compareTo(order) >= 0)
					keys[j] = new BigInteger(bitLength, r);
			}
			
			
		}
		//Decrypt feedback
		int resultOfComparison;
		if(host == null)
		{
			feedback[0] = ZKToolkit.decryptECElgamal(new CryptoDataArray(feedback), myPartOfKey, miniEnv);
			out.writeObject(new CryptoDataArray(feedback));
			resultOfComparison = (int) in.readObject();
		}
		else
		{
			feedback[0] = ZKToolkit.decryptECElgamal((CryptoData) in.readObject(), myPartOfKey, miniEnv);
			if(feedback[0].equals(inf)) resultOfComparison = 0;
			else if(feedback[0].equals(g)) resultOfComparison = -1;
			else resultOfComparison = 1;
			out.writeObject(-resultOfComparison);
		}
		System.out.println(resultOfComparison);

//		if(verified) System.out.println("Good bit commitment");
//		else 
//		{
//			System.out.println("LIAR BAD BIT COMMITMENT");
//			System.out.println(transcript.toString());
//		}
		
		out.flush();
		final long actualEnd = System.currentTimeMillis();
		System.out.println(counter);
		System.out.println("My sum is " + sum);
		if(resultOfComparison == 1) System.out.println("I have MORE HAHAHAHA");
		if(resultOfComparison == 0) System.out.println("We have equal amounts");
		if(resultOfComparison == -1) System.out.println("I have less :-(");
		System.out.println(actualEnd - endTime);
		

		System.out.println("Total execution time: " + (endTime - startTime) );
		try {
			arg0 = new FileWriter("Output_" + args[3]);
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		BufferedWriter out1 = new BufferedWriter(arg0);

		if(verify)
			out1.write("Success!\n");
		else 
		{
			
		}
		out1.write(String.format("Total execution time: %d\n", (endTime - startTime)));
		out1.flush();
		out.close();
		out1.close();
		out2.flush();
		out2.close();
		in.close();
		s.close();
		if(host != null) host.close();
	}

	private static void runProver(ZKPProtocol prover, ServerSocket host,
			ObjectInputStream in, ObjectOutputStream out, ECPedersenCommitment[] otherCommitments, Random r, ECPoint h, int bitLength, CryptoData miniEnv, CryptoData revMiniEnv, CryptoData environment, int proverIndex,
			CryptoData[][] acc, CryptoData[] input, StringBuilder transcript) throws IOException {

		BigInteger order = h.getCurve().getOrder();
		for(int i = 0; i < proverIndex; i++)
		{
			try {
				otherCommitments[i] = (ECPedersenCommitment) in.readObject();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
		}
		out.flush();
		for(int i = 0; i < proverIndex; i++)
		{
			ECPoint comm = otherCommitments[i].getCommitment(miniEnv);					
			CryptoData[] dataArrayInner = new CryptoData[2];
			CryptoData[] dataArrayOuter = new CryptoData[2];
			//System.out.printf("Making Verifier ZKPData:\n\ta[0] = %s\n\ta[1] = %s\n", acc[0], acc[1]);
			
			CryptoData[] bIntArray = new CryptoData[1];
			bIntArray[0] = acc[i][1];
			
			dataArrayInner[0] = new CryptoDataArray(bIntArray);
			bIntArray = new CryptoData[1];
			bIntArray[0] = new ECPointData(comm.add(h.multiply(acc[i][0].getBigInt().negate())));
			
			dataArrayInner[1] = new CryptoDataArray(bIntArray);
			
			dataArrayOuter[0] = new CryptoDataArray(dataArrayInner);
			
			bIntArray = new CryptoData[1];
			bIntArray[0] = new ECPointData(comm);
			
			dataArrayOuter[1] = new CryptoDataArray(bIntArray);
			CryptoData otherInput = new CryptoDataArray(dataArrayOuter);
			try {

				BigInteger random = new BigInteger(bitLength, r);
				while(random.compareTo(order) >= 0)
					random = new BigInteger(bitLength, r);
				BigInteger[] c = new BigInteger[] {new BigInteger(bitLength - 1, r),random};
				ECPedersenCommitment myCmt = new ECPedersenCommitment(c[0], c[1], miniEnv);

				ObjectInputStream[] inArray = {in}; 
				ObjectOutputStream[] outArray = {out}; 
				
				verify = prover.parallelZKProve(input[i], otherInput, environment, in, out, myCmt, miniEnv, c, transcript);
				if(!(verify)) {
//							System.out.println(myVerify + " " + otherVerify);
					break;
				}
				else othersSumCommitment = othersSumCommitment.multiplyCommitment(otherCommitments[i], miniEnv);
					
			} catch (ClassNotFoundException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e) {
				
				e.printStackTrace();
			}
		}
	}
	
}
