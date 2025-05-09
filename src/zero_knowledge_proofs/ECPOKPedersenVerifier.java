package zero_knowledge_proofs;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class ECPOKPedersenVerifier extends ZKPVerifier{

	//input format: [y]
	//a format:     [a]
	//z format:     [z_1, z_2]
	//enviroment format: [(c,g), h]
	@Override
	protected boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge, CryptoData environment) {
		// TODO Auto-generated method stub

		CryptoData[] ue = environment.getCryptoDataArray();
		ECCurve c = ue[0].getECCurveData();
		ECPoint g = ue[0].getECPointData(c);
		ECPoint h = ue[1].getECPointData(c);
		
		CryptoData[] ui = input.getCryptoDataArray();
		ECPoint y = ui[0].getECPointData(c);
		
		CryptoData[] ua = a.getCryptoDataArray();
		ECPoint init = ua[0].getECPointData(c);

		CryptoData[] uz = z.getCryptoDataArray();
		BigInteger z_1 = uz[0].getBigInt();
		BigInteger z_2 = uz[1].getBigInt();
		//check:  g^z_1*h^z_2 == y^c*a
		return (g.multiply(z_1).add(h.multiply(z_2)).equals(y.multiply(challenge).add(init)));
	}

}
