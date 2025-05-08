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
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class ProtocolMainECMixedMalWithComparisonMultiSig {
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
		ZKPProtocol ecSchnorr = new ECSchnorrProver();
		ZKPProtocol[][] provers = new ZKPProtocol[1][];
		CryptoData[][] environments = new CryptoData[1][];
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
		out.flush();
		ECPoint otherHalfH = curve.decodePoint((byte[]) in.readObject());
		
		ECPoint h = halfH.add(otherHalfH);
		
		ArrayList<KeyList> knownKeys = new ArrayList<KeyList>();
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
			if(stringData[0].length() > 2 && stringData[0].substring(0, 2).equals("//")) {
				if(debug != 0)  System.out.printf("Key Line Omitted:  %s\n", dataRow);
				continue;	//lines can be commented with //
			}
			if(stringData.length < 3) 
			{
				System.err.printf("Line rejected from Keys:  %s\n", dataRow);
				continue;				
			}
			
			
			KeyList keys = new KeyList();
			
			try
			{
				keys.id = Integer.parseInt(stringData[0]);
				keys.keys = new CryptoData[stringData.length / 2];
				keys.positions = new int[stringData.length / 2];
				for(int i = 0; i < keys.keys.length; i++)
				{
					keys.keys[i] = new BigIntData(new BigInteger(decoder.decode(stringData[(i+1) * 2])));
					keys.positions[i] = Integer.parseInt(stringData[((i+1) * 2) - 1]);
				}
				knownKeys.add(keys);
			}
			catch(Exception e)
			{
				System.err.println("Line failed in KeyFile:  Not parsed as numbers.  " + dataRow);
				e.printStackTrace(System.err);
				continue;
			}
		}
		
		knownKeys.add(null);
		int index = 0;
		int proverIndex = 0;
		int counter = 0;
		CryptoData[] proverInput = new CryptoData[blockSize];
		CryptoData[] verifierInput = new CryptoData[blockSize];
		CryptoData[][] acc = new CryptoData[blockSize][];
		BigInteger balance[] = new BigInteger[blockSize];

		ObjectInputStream[] inArray = {in}; 
		ObjectOutputStream[] outArray = {out};
		while((dataRow = br.readLine()) != null)
		{
			
			if(dataRow.length() == 0) continue;
			
			//String Format:  "Amount in account	Public Key" for each line. 
			String[] stringData = dataRow.split("\t");
			
			if(stringData[0].length() >= 2 && stringData[0].substring(0, 2).equals("//")) {
				if(debug != 0)  System.out.printf("Account Line Omitted:  %s\n", dataRow);
				continue;	//lines can be commented with //
			}
			if(stringData.length < 4) 
			{
				System.err.printf("Line rejected from accounts:  %s\n", dataRow);
				continue;				
			}
			int n = 0;
			int k = 0;
			if(counter % 2<<15 == 0)
			{
				out.flush();
				out.reset();
			}
			try
			{
				n = Integer.parseInt(stringData[1]);
				k = Integer.parseInt(stringData[2]);
				acc[proverIndex] =  new CryptoData[n];
				balance[proverIndex] = new BigInteger(stringData[0], 16);
				for(int i = 0; i < n; i++)
				{
					acc[proverIndex][i] = new ECPointData(curve.decodePoint(decoder.decode(stringData[i + 3])));
				}
			}
			catch(Exception e)
			{
				System.err.println("Line failed in AccountFile:  Not parsed correctly.  " + dataRow);
				continue;
			}
			KeyList keys = knownKeys.get(index);
			BigInteger random;
			ECPedersenCommitment commitment;
			if(provers.length < n)
			{
				ZKPProtocol[][] temp = new ZKPProtocol[n][];
				CryptoData[][] temp2 = new CryptoData[n][];
				for(int i = 0; i < provers.length; i++)
				{
					temp[i] = provers[i];
					temp2[i] = environments[i];
				}
				provers = temp;
				environments = temp2;
				provers[n-1] = new ZKPProtocol[n];
				environments[n-1] = new CryptoData[n];
				
				ZKPProtocol keyProtocol = VarianceToolkit.createMultiSigProofNaive(n, k, ecSchnorr);

				provers[n-1][k-1] = VarianceToolkit.createVarianceMultiSigProof(keyProtocol, ecSchnorr);
				
				CryptoData keyEnv = VarianceToolkit.createMultiSigEnvironmentNaive(n, k, miniEnv);
				environments[n-1][k-1] = VarianceToolkit.createVarianceEnvironment(keyEnv, miniEnv);
			}
			else if(provers[n-1] == null)
			{
				provers[n-1] = new ZKPProtocol[n];
				environments[n-1] = new CryptoData[n];

				ZKPProtocol keyProtocol = VarianceToolkit.createMultiSigProofNaive(n, k, ecSchnorr);

				provers[n-1][k-1] = VarianceToolkit.createVarianceMultiSigProof(keyProtocol, ecSchnorr);
				
				CryptoData keyEnv = VarianceToolkit.createMultiSigEnvironmentNaive(n, k, miniEnv);
				environments[n-1][k-1] = VarianceToolkit.createVarianceEnvironment(keyEnv, miniEnv);
			
			}
			else if(provers[n-1][k-1] == null)
			{
				ZKPProtocol keyProtocol = VarianceToolkit.createMultiSigProofNaive(n, k, ecSchnorr);

				provers[n-1][k-1] = VarianceToolkit.createVarianceMultiSigProof(keyProtocol, ecSchnorr);
				
				CryptoData keyEnv = VarianceToolkit.createMultiSigEnvironmentNaive(n, k, miniEnv);
				environments[n-1][k-1] = VarianceToolkit.createVarianceEnvironment(keyEnv, miniEnv);
			}
			
			BigInteger pcKey;
			do{
				pcKey = new BigInteger(bitLength, r);
			}while (pcKey.compareTo(order) >= 0);
			if(keys != null && keys.id == counter && keys.keys.length >= k){ 
				index++;
				commitment = new ECPedersenCommitment(balance[proverIndex], pcKey, miniEnv);
				ECPoint comm = commitment.getCommitment(miniEnv);
				CryptoData keyData = VarianceToolkit.createMultiSigProverDataNaive(n, k, acc[proverIndex], keys.keys, keys.positions, miniEnv, ecSchnorr, order, r);
				proverInput[proverIndex] = VarianceToolkit.createVarianceProverData(keyData, pcKey, comm, balance[proverIndex], miniEnv, true, r);
				sumKey = sumKey.add(pcKey).mod(order);
				sum = sum.add(balance[proverIndex]);
			}
			else
			{
				sumKey = sumKey.add(pcKey).mod(order);
				
				commitment = new ECPedersenCommitment(BigInteger.ZERO, pcKey, miniEnv);
				ECPoint comm = commitment.getCommitment(miniEnv);
				CryptoData keyData = VarianceToolkit.createMultiSigSimulatorDataNaive(n, k, acc[proverIndex], ecSchnorr, order, r);
				proverInput[proverIndex] = VarianceToolkit.createVarianceProverData(keyData, pcKey, comm, balance[proverIndex], miniEnv, false, r);
			}
			out.writeObject(commitment);
			out.flush();
			counter++;
			proverIndex++;
			if((proverIndex == blockSize || (!br.ready() && proverIndex != 0)))
			{
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
					CryptoData keyVerifierData = VarianceToolkit.createMultiSigVerifierInputsNaive(n, k, acc[i], ecSchnorr);
					verifierInput[i] = VarianceToolkit.createVarianceVerifierData(keyVerifierData, comm, balance[i], miniEnv);
					
					try {

						random = new BigInteger(bitLength, r);
						while(random.compareTo(order) >= 0)
							random = new BigInteger(bitLength, r);
						BigInteger[] c = new BigInteger[] {new BigInteger(bitLength - 1, r),random};
						ECPedersenCommitment myCmt = new ECPedersenCommitment(c[0], c[1], miniEnv);
						verify = provers[n-1][k-1].parallelZKProve(proverInput[i], verifierInput[i], environments[n-1][k-1], in, out, myCmt, miniEnv, c, transcript);
						if(!(verify)) {
//									System.out.println(myVerify + " " + otherVerify);
							break;
						}
						else
						{
							othersSumCommitment = othersSumCommitment.multiplyCommitment(otherCommitments[i], miniEnv);
						}
							
					} catch (ClassNotFoundException | MultipleTrueProofException | NoTrueProofException
							| ArraySizesDoNotMatchException e) {
						
						e.printStackTrace();
					}
				}
				out2.write(transcript.toString());
				transcript.setLength(0);
				out2.flush();
				out.flush();
				proverIndex = 0;
			}
		}
		if(proverIndex != 0)
		{
			System.out.println("Argh...");
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

			/*
		ECPedersenOwnedBitwiseCommitment ecBits = null;
		try {
			ecBits = VarianceToolkit.ECConvertToBits(sum, sumKey, 20, miniEnv, r);
		} catch (TooFewBitsException e1) {
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
		if(VarianceToolkit.consistantTableEncryptionProver.parallelZKProve(pInputs, new CryptoData[] {vInputs}, tableProofEnv, inArray, outArray, myCmt, miniEnv, c, null))
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

			if(!VarianceToolkit.tableEqualityProver.parallelZKProve(shufflePInputs, new CryptoData[] {shuffleVInputs}, shuffleProofEnv, inArray, outArray, myCmt, miniEnv, c, null))
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
			VarianceToolkit.consistantTableEncryptionProver.parallelZKProve(pInputs, new CryptoData[] {vInputs}, tableProofEnv, inArray, outArray, myCmt, miniEnv, c, null);
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
				*/
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
//		if(resultOfComparison == 1) System.out.println("I have MORE HAHAHAHA");
//		if(resultOfComparison == 0) System.out.println("We have equal amounts");
//W		if(resultOfComparison == -1) System.out.println("I have less :-(");
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

	
}
