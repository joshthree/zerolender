package zero_knowledge_proofs;

import java.math.BigInteger;
import java.util.ArrayList;

import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class ZeroKnowledgeAndProver extends ZKPProtocol {

	ZKPProtocol[] p;
	public ZeroKnowledgeAndProver(ZKPProtocol[] p) {
		this.p = p.clone();
	}
	@Override
	protected ArrayList<BigInteger> internalNullChallenges(CryptoData response, BigInteger challenge, ArrayList<BigInteger> list) {
		if(response == null) {
			list.add(challenge);
			return list;
		}
		if(!response.hasNull()) return list;
		CryptoData[] z = response.getCryptoDataArray();
		for(int i = 0; i < z.length; i++)
		{
			if(z[i] == null) {
				list.add(challenge);
			}
			else if(z[i].hasNull()){
				p[i].internalNullChallenges(z[i], challenge, list);
			}
		}
		return list;
	}
	@Override
	public CryptoData initialComm(CryptoData input, CryptoData packedEnvironment)
			throws ArraySizesDoNotMatchException, MultipleTrueProofException, NoTrueProofException {

		if(input == null) return null;
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] environment = packedEnvironment.getCryptoDataArray();
		CryptoData[] out = new CryptoData[in.length];
		if(in.length != p.length) throw  new ArraySizesDoNotMatchException("" + p.length + " != " + in.length);

		for(int i = 0; i < p.length; i++)
		{
			if(in[i] == null)
				out[i] = null;
			else 
				out[i] = p[i].initialComm(in[i], environment[i]);
		}
		
		return new CryptoDataArray(out);
	}

	@Override
	public CryptoData initialCommSim(CryptoData input, BigInteger challenge, CryptoData packedEnvironment)
			throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		if(input == null) return null;
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] environment = packedEnvironment.getCryptoDataArray();
		CryptoData[] out = new CryptoData[p.length];
		for(int i = 0; i < p.length; i++)
		{
			if(in[i] == null)
				out[i] = null;
			else 
				out[i] = p[i].initialCommSim(in[i], challenge, environment[i]);
		}
		
		return new CryptoDataArray(out);
	}

	@Override
	public CryptoData calcResponse(CryptoData input, BigInteger challenge, CryptoData packedEnvironment)
			throws NoTrueProofException, MultipleTrueProofException {

		if(input == null) return null;
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] environment = packedEnvironment.getCryptoDataArray();
		CryptoData[] out = new CryptoData[in.length];
		for(int i = 0; i < p.length; i++)
		{
			if(in[i] == null)
				out[i] = null;
			else 
				out[i] = p[i].calcResponse(in[i], challenge, environment[i]);
		}
		
		return new CryptoDataArray(out);
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData input) {
		if(input == null) return null;
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] out = new CryptoData[in.length];
		for(int i = 0; i < p.length; i++)
			{
				if(in[i] == null)
					out[i] = null;
				else 
					out[i] = p[i].simulatorGetResponse(in[i]);
		}
		
		return new CryptoDataArray(out);
	}

	@Override
	public boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge, CryptoData environment) {
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] initialComm = a.getCryptoDataArray();
		CryptoData[] responses = z.getCryptoDataArray();
		CryptoData[] environments = environment.getCryptoDataArray();
		boolean toReturn = true;
		for(int i = 0; i < in.length; i++)
		{
			if(p[i].verifyResponse(in[i], initialComm[i], responses[i], challenge, environments[i]) == false)
			{
				System.out.println("AND failed on proof " + i);
				System.out.println(p[i]);
				toReturn = false;
			}
		}
		return toReturn;
 	}

	@Override
	public String toString()
	{
		String toReturn = "AND(";
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

		if(publicInput == null) return null;
		CryptoData[] in = publicInput.getCryptoDataArray();
		CryptoData[] s = secrets.getCryptoDataArray();
		
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] out = new CryptoData[in.length];
		if(in.length != p.length || s.length != p.length) throw  new ArraySizesDoNotMatchException("" + p.length + " != " + in.length);

		for(int i = 0; i < p.length; i++)
		{
			if(in[i] == null)
				out[i] = null;
			else 
				out[i] = p[i].initialComm(in[i], s[i], e[i]);
		}
		
		return new CryptoDataArray(out);
	}
	@Override
	public CryptoData initialCommSim(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment)
			throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		if(publicInput == null || secrets == null) return null;
		CryptoData[] in = publicInput.getCryptoDataArray();
		CryptoData[] s = secrets.getCryptoDataArray();
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] out = new CryptoData[p.length];
		for(int i = 0; i < p.length; i++)
		{
			if(in[i] == null)
				out[i] = null;
			else 
				out[i] = p[i].initialCommSim(in[i], s[i], challenge, e[i]);
		}
		
		return new CryptoDataArray(out);
	}
	@Override
	public CryptoData calcResponse(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment) throws NoTrueProofException, MultipleTrueProofException {

		if(publicInput == null) return null;
		CryptoData[] in = publicInput.getCryptoDataArray();
		CryptoData[] s = secrets.getCryptoDataArray();
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] out = new CryptoData[in.length];
		for(int i = 0; i < p.length; i++)
		{
			if(in[i] == null)
				out[i] = null;
			else 
				out[i] = p[i].calcResponse(in[i], s[i], challenge, e[i]);
		}
		
		return new CryptoDataArray(out);
	}
	@Override
	public CryptoData simulatorGetResponse(CryptoData publicInput, CryptoData secrets) {
		if(secrets == null) return null;
		CryptoData[] sIn = secrets.getCryptoDataArray();
		CryptoData[] pIn = publicInput.getCryptoDataArray();
		CryptoData[] out = new CryptoData[p.length];
		for(int i = 0; i < p.length; i++)
			{
				if(sIn[i] == null)
					out[i] = null;
				else 
					out[i] = p[i].simulatorGetResponse(pIn[i], sIn[i]);
		}
		
		return new CryptoDataArray(out);
	}
}
