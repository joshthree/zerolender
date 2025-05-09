package zero_knowledge_proofs;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.InputMismatchException;

import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.Matrix;
import zero_knowledge_proofs.CryptoData.MatrixInterface;

public class ZeroKnowledgeThreshold extends ZKPProtocol {
	private static HashMap<int[], MatrixInterface> history;
	
	private ZKPProtocol[] p;

	private int numSimulated;
	private BigInteger challengePrime;
	
	public ZeroKnowledgeThreshold(ZKPProtocol[] p, int threshholdK, BigInteger challengePrime) {
		this.p = p.clone();
		numSimulated = p.length - threshholdK;
		this.challengePrime = challengePrime;
	}



	@Override
	protected ArrayList<BigInteger> internalNullChallenges(CryptoData response, BigInteger challenge, ArrayList<BigInteger> list) {
		if(response == null) {
			list.add(challenge);
			return list;
		}
		if(!response.hasNull()) return list;
		CryptoData[] z = response.getCryptoDataArray();
		CryptoData[] c = z[z.length-1].getCryptoDataArray();
		for(int i = 0; i < z.length-1; i++) {
			if(z[i] == null) {
				list.add(c[i].getBigInt());
			}
			else if(z[i].hasNull()){
				p[i].internalNullChallenges(z[i], c[i].getBigInt(), list);
			}
		}
		return list;
	}


	//input format:  [[(inputs for p1)],[(inputs for p2)],...[(inputs for pn)],[simulatedChallenges]
	//
	@Override
	public CryptoData initialComm(CryptoData input, CryptoData packedEnvironment) throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		if(input == null) return null;

		CryptoData[] environment = packedEnvironment.getCryptoDataArray();
		CryptoData[] i = input.getCryptoDataArray(); 
		CryptoData[] simulatedChallenges = i[i.length - 1].getCryptoDataArray();
		CryptoData[] o = new CryptoData[p.length];
		if (simulatedChallenges.length != p.length) 
		{
			System.out.println(i[i.length - 1]);
			throw new ArraySizesDoNotMatchException("" + p.length + " != " + simulatedChallenges.length);
		}
		int fakeProofFound = 0;

		for(int j = 0; j < o.length; j++)
		{

			BigInteger c = simulatedChallenges[j].getBigInt();
			if(!c.equals(BigInteger.ZERO)) 
			{
				if(i[j] == null)
					o[j] = null;
				else
					o[j] = p[j].initialCommSim(i[j], c, environment[j]);
				fakeProofFound++;
			}
			else
			{
				if(i[j] == null)
					o[j] = null;
				else
					o[j] = p[j].initialComm(i[j], environment[j]);

			}
		}
		if(fakeProofFound != numSimulated) 
		{
			throw new InputMismatchException("Incorrect number of simulated proofs.");
		}
		return new CryptoDataArray(o);
	}

	//input format:  [[(inputs for p1)],[(inputs for p2)],...,[inputs for pn],[simulatedChallenges]]  
	//Exactly, one challenge should be 0.  If no challenges are 0, it will replace the last challenge to accommodate the challenge argument.
	//If there is more than 1 missing challenge, it will throw a MultipleTrueProofException.
	//If the simulated challenges array is smaller than the number of protocols, then it will throw an ArraySizesDoNotMatchException.
	@Override
	public CryptoData initialCommSim(CryptoData input, BigInteger challenge, CryptoData packedEnvironment) throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		if(input == null) return null;
		CryptoData[] environment = packedEnvironment.getCryptoDataArray();
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] out = new CryptoData[p.length];
		CryptoData[] coefficients = in[p.length].getCryptoDataArray();
		try {
			if(coefficients.length != numSimulated) throw new ArraySizesDoNotMatchException("" + numSimulated + " != " + coefficients.length);
		}catch(NullPointerException e)
		{
			System.out.println(input);
			throw new NullPointerException(e.getMessage());
		}
		BigInteger[] challenges = new BigInteger[p.length];
		BigInteger[] coefficientsBigInt = new BigInteger[coefficients.length];
		BigInteger[] values = new BigInteger[p.length];
		for(int i = 0; i < values.length; i++) {
			values[i] = BigInteger.valueOf(i);
		}
		for(int i = 0; i < coefficientsBigInt.length; i++) {
			coefficientsBigInt[i] = coefficients[i].getBigInt();
		}
		for(int i = 0; i < challenges.length; i++) {
			challenges[i] = coefficients[0].getBigInt();
			for(int j = 0; j < coefficients.length;j++) {
				challenges[i] = challenges[i].add(coefficientsBigInt[j].modPow(values[j], challengePrime));
			}
		}
		for(int j = 0; j < p.length-1; j++)
		{
			BigInteger c = challenges[j];
				if(in[j] == null) 
					out[j] = null;
				else
					out[j] = p[j].initialCommSim(in[j], c, environment[j]);
		}
		return new CryptoDataArray(out);
	}

	@Override
	public CryptoData calcResponse(CryptoData input, BigInteger challenge, CryptoData packedEnvironment) throws NoTrueProofException, MultipleTrueProofException {
		if(input == null) return null;
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] out = new CryptoData[p.length + 1];
		CryptoData[] environment = packedEnvironment.getCryptoDataArray();
		CryptoData[] simulatedChallenges = in[in.length - 1].getCryptoDataArray().clone();
		BigInteger[][] simChallenges = new BigInteger[numSimulated+1][1];
		int[] positions = new int[numSimulated]; 
		
		simChallenges[0][0] = challenge;
		int count = 0;
		for(int i = 0; i < p.length; i++)
		{
			BigInteger c = simulatedChallenges[i].getBigInt();
			if(c.equals(BigInteger.ZERO)) {
				positions[count] = i+1;
				count++;
				simChallenges[count][0] = c;
			}
		}
		MatrixInterface m = history.get(positions);
		if(m == null){
			BigInteger[][] basic = new BigInteger[numSimulated+1][numSimulated+1];
			basic[0][0] = BigInteger.ONE;
			for(int i = 1; i < numSimulated+1; i++) {
				basic[0][i] = BigInteger.ZERO;
			}
			for(int i = 1; i < numSimulated+1; i++) {
				basic[i][0] = BigInteger.ONE;
				for(int j = 1; j < numSimulated+1; j++) {
					basic[i][j] = BigInteger.valueOf(j+1).modPow(BigInteger.valueOf(i+1), challengePrime);
				}
			}
			MatrixInterface mainM = new Matrix(basic, challengePrime);
			m = mainM.getInverse();
			history.put(positions, m);
		}
		BigInteger[][] coefficients = m.multiply(new Matrix(simChallenges, challengePrime)).getMatrix();
		CryptoData[] toReturn = new CryptoData[p.length+1];
		count = 0;
		BigInteger[] coefficientsToReturn = new BigInteger[numSimulated];
		for(int i = 0; i < p.length; i++) {
			if(positions[count] == i) {
				toReturn[i] = p[i].simulatorGetResponse(in[i]);
				count++;
			}
			else {
				BigInteger c = coefficients[0][0];
				for(int j = 0; j < numSimulated; j++) {
					c = c.add(coefficients[j+1][0].multiply(BigInteger.valueOf(j+1).modPow(BigInteger.valueOf(i+1), challengePrime)));
				}
				toReturn[i] = p[i].calcResponse(in[i], coefficients[i][0], environment[i]);
			}
		}
		
		for(int i = 0; i < numSimulated; i++) {
			coefficientsToReturn[i] = coefficients[i+1][0];
		}
		toReturn[p.length] = new CryptoDataArray(coefficientsToReturn);
		return new CryptoDataArray(toReturn);
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData input) {
		if(input == null) return null;
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] simulatedCoefficients = in[in.length-1].getCryptoDataArray();
		CryptoData[] out = new CryptoData[p.length + 1];
		for(int i = 0; i < in.length-1; i++)
		{
			if(in[i] == null) 
				out[i] = null;
			else
				out[i] = p[i].simulatorGetResponse(in[i]);
		}
		out[p.length] = new CryptoDataArray(simulatedCoefficients);
		CryptoData toReturn = new CryptoDataArray(out);

		return toReturn;
	}
	@Override
	public boolean verifyResponse(CryptoData input, CryptoData a_unopened, CryptoData z_unopened, BigInteger challenge, CryptoData environments) {
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] a = a_unopened.getCryptoDataArray();
		CryptoData[] z = z_unopened.getCryptoDataArray();
		CryptoData[] e = environments.getCryptoDataArray();
		CryptoData[] coefficients = z[z.length-1].getCryptoDataArray();
		//		System.out.println("V:\tin = " + input);
		//		System.out.println("V:\ta  = " + a_unopened);
		//		System.out.println("V:\tz  = " + z_unopened);
		//		System.out.println("V:\tc  = " + challenge);
		boolean toReturn = true;
		boolean flag;
		BigInteger[] challenges = new BigInteger[p.length];
		for(int i = 0; i < p.length; i++)
		{ 
			BigInteger c = challenge;

			for(int j = 0; j != coefficients.length; j++) {
				c = coefficients[j].getBigInt().multiply(BigInteger.valueOf(j+2).modPow(BigInteger.valueOf(i+1), challengePrime));
			}
			
			flag = p[i].verifyResponse(in[i], a[i], z[i], c, e[i]);
			if(!flag) 
			{
				System.out.println("PT failed on proof " + i);
				toReturn = false;
			}
		}

		return toReturn;
	}
	@Override
	public String toString()
	{
		String toReturn = "PT(";
		for(int i = 0; i < p.length; i++)
		{
			if(i != 0) toReturn += ", ";
			toReturn += p[i].toString();
		}
		return toReturn + ")";
	}



	@Override
	public CryptoData initialComm(CryptoData publicInput, CryptoData secrets, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		if(publicInput == null || secrets == null) return null;

		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] i = publicInput.getCryptoDataArray(); 
		CryptoData[] s = secrets.getCryptoDataArray(); 
		CryptoData[] simulatedChallenges = s[s.length - 1].getCryptoDataArray();
		//System.out.println("In PT: " + i[i.length - 1]);
		CryptoData[] o = new CryptoData[p.length];
		if (simulatedChallenges.length != p.length) 
		{
			System.out.println(i[i.length - 1]);
			throw new ArraySizesDoNotMatchException("" + p.length + " != " + simulatedChallenges.length);
		}
		if (s.length - 1 != p.length) 
		{
			System.out.println(i[i.length - 1]);
			throw new ArraySizesDoNotMatchException("" + s.length + " - 1 != " + p.length);
		}
		boolean trueProofFound = false;

		for(int j = 0; j < o.length; j++)
		{

			BigInteger c = simulatedChallenges[j].getBigInt();
			if(!c.equals(BigInteger.ZERO)) 
			{
				if(i[j] == null)
					o[j] = null;
				else
					o[j] = p[j].initialCommSim(i[j], s[j], c, e[j]);
			}
			else
			{
				if(!trueProofFound)
				{
					trueProofFound = true;
				}
				else throw new MultipleTrueProofException();

				if(i[j] == null)
					o[j] = null;
				else
					o[j] = p[j].initialComm(i[j], s[j], e[j]);

			}
		}
		if(!trueProofFound) 
		{
			throw new NoTrueProofException();
		}
		return new CryptoDataArray(o);
	}



	@Override
	public CryptoData initialCommSim(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment)
					throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		if(publicInput == null || secrets == null) return null;
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] in = publicInput.getCryptoDataArray();
		CryptoData[] s = secrets.getCryptoDataArray();
		CryptoData[] out = new CryptoData[p.length];
		CryptoData[] simulatedChallenges = in[p.length].getCryptoDataArray();
		if(simulatedChallenges.length != p.length) throw new ArraySizesDoNotMatchException("" + p.length + " != " + simulatedChallenges.length);
		boolean trueProofFound = false;
		BigInteger trueChallenge = challenge;
		int trueProof = -1;

		for(int j = 0; j < p.length-1; j++)
		{
			BigInteger c = simulatedChallenges[j].getBigInt();
			if(c.equals(BigInteger.ZERO))
			{
				if(trueProofFound)
				{
					throw new MultipleTrueProofException();
				} else {
					trueProof = j;
					trueProofFound = true;
				}
			}
			else
			{
				if(in[j] == null) 
					out[j] = null;
				else
					out[j] = p[j].initialCommSim(in[j], s[j], c, e[j]);
				trueChallenge = trueChallenge.xor(c);
			}
		}
		if(trueProofFound)
		{
			BigInteger c = simulatedChallenges[p.length-1].getBigInt();
			if(in[p.length-1] == null)
				out[p.length-1] = null;
			else
				out[p.length - 1] = p[p.length - 1].initialCommSim(in[p.length-1], s[p.length-1], c, e[p.length-1]);
			trueChallenge = trueChallenge.xor(c);
			simulatedChallenges[trueProof] = new BigIntData(trueChallenge);
			if(in[trueProof] == null)
				out[trueProof] = null;
			else
				out[trueProof] = p[trueProof].initialCommSim(in[trueProof], s[trueProof], trueChallenge, e[trueProof]);
		}
		else {
			throw new NoTrueProofException();
		}
		return new CryptoDataArray(out);
	}



	@Override
	public CryptoData calcResponse(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment) throws NoTrueProofException, MultipleTrueProofException {
		if(publicInput == null || secrets == null) return null;
		CryptoData[] in = publicInput.getCryptoDataArray();
		CryptoData[] s = secrets.getCryptoDataArray();
		CryptoData[] out = new CryptoData[p.length + 1];
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] simulatedChallenges = s[s.length - 1].getCryptoDataArray();
		
		BigInteger[][] simChallenges = new BigInteger[numSimulated+1][1];
		int[] positions = new int[numSimulated]; 
		
		simChallenges[0][0] = challenge;
		int count = 0;
		for(int i = 0; i < p.length; i++)
		{
			BigInteger c = simulatedChallenges[i].getBigInt();
			if(c.equals(BigInteger.ZERO)) {
				positions[count] = i+1;
				count++;
				simChallenges[count][0] = c;
			}
		}
		MatrixInterface m = history.get(positions);
		if(m == null){
			BigInteger[][] basic = new BigInteger[numSimulated+1][numSimulated+1];
			basic[0][0] = BigInteger.ONE;
			for(int i = 1; i < numSimulated+1; i++) {
				basic[0][i] = BigInteger.ZERO;
			}
			for(int i = 1; i < numSimulated+1; i++) {
				basic[i][0] = BigInteger.ONE;
				for(int j = 1; j < numSimulated+1; j++) {
					basic[i][j] = BigInteger.valueOf(j+1).modPow(BigInteger.valueOf(i+1), challengePrime);
				}
			}
			MatrixInterface mainM = new Matrix(basic, challengePrime);
			m = mainM.getInverse();
			history.put(positions, m);
		}
		BigInteger[][] coefficients = m.multiply(new Matrix(simChallenges, challengePrime)).getMatrix();
		CryptoData[] toReturn = new CryptoData[p.length+1];
		count = 0;
		BigInteger[] coefficientsToReturn = new BigInteger[numSimulated];
		for(int i = 0; i < p.length; i++) {
			if(positions[count] == i) {
				toReturn[i] = p[i].simulatorGetResponse(in[i], s[i]);
				count++;
			}
			else {
				BigInteger c = coefficients[0][0];
				for(int j = 0; j < numSimulated; j++) {
					c = c.add(coefficients[j+1][0].multiply(BigInteger.valueOf(j+1).modPow(BigInteger.valueOf(i+1), challengePrime)));
				}
				toReturn[i] = p[i].calcResponse(in[i], coefficients[i][0], e[i]);
			}
		}
		
		for(int i = 0; i < numSimulated; i++) {
			coefficientsToReturn[i] = coefficients[i+1][0];
		}
		toReturn[p.length] = new CryptoDataArray(coefficientsToReturn);
		return new CryptoDataArray(toReturn);
	}
//TODO


	@Override
	public CryptoData simulatorGetResponse(CryptoData publicInput, CryptoData secrets) {
		if(secrets == null) return null;
		CryptoData[] sIn = secrets.getCryptoDataArray();
		CryptoData[] pIn = publicInput.getCryptoDataArray();
		CryptoData[] simulatedChallenges = sIn[sIn.length-1].getCryptoDataArray();
		CryptoData[] out = new CryptoData[p.length + 1];
		for(int i = 0; i < pIn.length; i++)
		{
			if(sIn[i] == null) 
				out[i] = null;
			else
				out[i] = p[i].simulatorGetResponse(pIn[i], sIn[i]);
		}
		out[p.length] = new CryptoDataArray(simulatedChallenges);
		CryptoData toReturn = new CryptoDataArray(out);

		return toReturn;
	}
	
	
}
