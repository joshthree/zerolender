package zero_knowledge_proofs;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class ECEqualDiscreteLogsVerifier extends ZKPVerifier {

	@Override
	protected boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge,
			CryptoData environment) {
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] resp = z.getCryptoDataArray();
		CryptoData[] i = input.getCryptoDataArray();
		CryptoData[] a_pack = a.getCryptoDataArray();
		
		ECCurve c = e[0].getECCurveData();
		ECPoint g = e[0].getECPointData(c);
		ECPoint h = e[1].getECPointData(c);
		ECPoint y_g = i[0].getECPointData(c);
		ECPoint y_h = i[1].getECPointData(c);
		BigInteger zNumber = resp[0].getBigInt();
		ECPoint a_1 = a_pack[0].getECPointData(c);
		ECPoint a_2 = a_pack[1].getECPointData(c);
		return (((y_g.multiply(challenge).add(a_1))).equals(g.multiply(zNumber)) && ((y_h.multiply(challenge).add(a_2))).equals(h.multiply(zNumber)));

	}

}
