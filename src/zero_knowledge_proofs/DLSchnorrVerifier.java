package zero_knowledge_proofs;

import java.math.BigInteger;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class DLSchnorrVerifier extends ZKPVerifier {


	//input format:  [y]

	@Override
	protected boolean verifyResponse(CryptoData input, CryptoData initial_comm, CryptoData response, BigInteger challenge,
			CryptoData environment) {
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] resp = response.getCryptoDataArray();
		CryptoData[] i = input.getCryptoDataArray();
		CryptoData[] a_pack = initial_comm.getCryptoDataArray();
		
		BigInteger y = i[0].getBigInt();
		BigInteger p = e[0].getBigInt();
		BigInteger g = e[1].getBigInt();
		BigInteger z = resp[0].getBigInt();
		BigInteger a = a_pack[0].getBigInt();
		
	//	return (a * y^c) mod p == (g^z) mod p 
		//System.out.printf("V:\t%s ?= %s\n", (i[0].modPow(challenge, e[1]).multiply(a[0])).mod(e[1]), e[0].modPow(z[0], e[1]));
		return ((y.modPow(challenge, p).multiply(a)).mod(p)).equals(g.modPow(z, p)) ;
	}
}
