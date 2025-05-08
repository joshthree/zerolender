package zero_knowledge_proofs;

import java.math.BigInteger;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class ZeroKnowledgeOrVerifier extends ZKPVerifier {
	private ZKPVerifier[] v;

	public ZeroKnowledgeOrVerifier(ZKPVerifier[] verifiers) {
		v = verifiers.clone();
	}

	@Override
	protected boolean verifyResponse(CryptoData input, CryptoData a_unopened, CryptoData z_unopened, BigInteger challenge, CryptoData environments) {
		CryptoData[] in = input.getCryptoDataArray();
		CryptoData[] a = a_unopened.getCryptoDataArray();
		CryptoData[] z = z_unopened.getCryptoDataArray();
		CryptoData[] e = environments.getCryptoDataArray();
		CryptoData[] challenges = z[z.length-1].getCryptoDataArray();
		
//		System.out.println("V:\tin = " + input);
//		System.out.println("V:\ta  = " + a_unopened);
//		System.out.println("V:\tz  = " + z_unopened);
//		System.out.println("V:\tc  = " + challenge);
		boolean toReturn = true;
		
		for(int i = 0; i < v.length; i++)
		{ 
			BigInteger c = challenges[i].getBigInt();
			challenge = challenge.xor(c);
			if(v[i].verifyResponse(in[i], a[i], z[i], c, e[i]) != true) 
			{
				
				return false;
			}
		}
		if(challenge.equals(BigInteger.ZERO) == false)
		{
			System.out.println("Bad Challenge");
			toReturn =  false;
		}
		return toReturn;
	}

}
