package zero_knowledge_proofs;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class ECSchnorrVerifier extends ZKPVerifier {


	//input format:  [y]

	@Override
	protected boolean verifyResponse(CryptoData input, CryptoData initial_comm, CryptoData response, BigInteger challenge,
			CryptoData environment) {
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] resp = response.getCryptoDataArray();
		CryptoData[] i = input.getCryptoDataArray();
		CryptoData[] a_pack = initial_comm.getCryptoDataArray();
		
		ECCurve c = e[0].getECCurveData();
		ECPoint g = e[0].getECPointData(c);
		ECPoint y = i[0].getECPointData(c);
		BigInteger z = resp[0].getBigInt();
		ECPoint a = a_pack[0].getECPointData(c);
		
	//	return (a * y^c) mod p == (g^z) mod p 
//		if(!((y.multiply(challenge).add(a))).equals(g.multiply(z))) System.out.printf("V:\t%s ?= %s\n", (y.multiply(challenge).add(a)).normalize(),g.multiply(z).normalize());
		return ((y.multiply(challenge).add(a))).equals(g.multiply(z)) ;
	}
}
