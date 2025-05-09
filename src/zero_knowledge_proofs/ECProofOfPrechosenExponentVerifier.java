package zero_knowledge_proofs;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class ECProofOfPrechosenExponentVerifier extends ZKPVerifier {
	//input: [origBase (m), newMessage(m^x), commitment (g^x*h^t)]
	@Override
	protected boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge,
			CryptoData environment) {

		CryptoData[] e = environment.getCryptoDataArray();
		ECCurve c = e[0].getECCurveData();
		ECPoint g = e[0].getECPointData(c);
		ECPoint h = e[1].getECPointData(c);
		
		CryptoData[] i = input.getCryptoDataArray();
		ECPoint m = i[0].getECPointData(c);
		ECPoint newM = i[1].getECPointData(c);
		ECPoint comm = i[2].getECPointData(c);
		
		CryptoData[] init = a.getCryptoDataArray();
		ECPoint a1 = init[0].getECPointData(c);
		ECPoint a2 = init[1].getECPointData(c);
		
		CryptoData[] resp = z.getCryptoDataArray();
		BigInteger z1 = resp[0].getBigInt();
		BigInteger z2 = resp[1].getBigInt();
		
		
		return (((newM.multiply(challenge).add(a1)).equals(m.multiply(z1))) && ((comm.multiply(challenge).add(a2)).equals(g.multiply(z1).add(h.multiply(z2)))));
	}

}
