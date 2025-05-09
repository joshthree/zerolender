package zero_knowledge_proofs;

import java.math.BigInteger;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class ZeroKnowledgeAndVerifier extends ZKPVerifier { 

	ZKPVerifier[] v;
	public ZeroKnowledgeAndVerifier(ZKPVerifier[] v) {
		this.v = v;
	}

	@Override
	protected boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge, CryptoData environment) {
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] initialComm = a.getCryptoDataArray();
		CryptoData[] responses = z.getCryptoDataArray();
		CryptoData[] environments = environment.getCryptoDataArray();
		boolean toReturn = true;
		for(int i = 0; i < in.length; i++)
		{
			if(v[i].verifyResponse(in[i], initialComm[i], responses[i], challenge, environments[i]) == false)
			{
				
				System.out.println("AND failed on proof " + i);
				System.out.println(v[i]);
				return false;
			}
		}
		return toReturn;
 	}

}
