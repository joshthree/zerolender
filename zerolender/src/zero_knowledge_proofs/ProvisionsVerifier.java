package zero_knowledge_proofs;

import java.math.BigInteger;

import zero_knowledge_proofs.CryptoData.CryptoData;

public class ProvisionsVerifier extends ZKPVerifier {
	//        [0      , 1         , 2  , 3  ]
	//input:  [account, public key, p_i, l_i]
	@Override
	protected boolean verifyResponse(CryptoData input, CryptoData a, CryptoData z, BigInteger challenge, CryptoData environment) {
		CryptoData[] inputs = input.getCryptoDataArray();
		CryptoData[] env = environment.getCryptoDataArray();
		CryptoData[] resp = z.getCryptoDataArray();
		CryptoData[] init = a.getCryptoDataArray();
		
		BigInteger b = inputs[0].getBigInt();
		BigInteger y = inputs[1].getBigInt();
		BigInteger pComm = inputs[2].getBigInt();
		BigInteger lComm = inputs[3].getBigInt();
		
		BigInteger g = env[0].getBigInt();
		BigInteger p = env[1].getBigInt();
		BigInteger h = env[2].getBigInt();
		
		BigInteger r_s = resp[0].getBigInt();
		BigInteger r_v = resp[1].getBigInt();
		BigInteger r_t = resp[2].getBigInt();
		BigInteger r_x = resp[3].getBigInt();
		BigInteger c_1 = resp[4].getBigInt();
		BigInteger r_0 = resp[5].getBigInt();
		BigInteger r_1 = resp[6].getBigInt();
		
		BigInteger a_1 = init[0].getBigInt();
		BigInteger a_2 = init[1].getBigInt();
		BigInteger a_3 = init[2].getBigInt();
		BigInteger binA_0 = init[3].getBigInt();
		BigInteger binA_1 = init[4].getBigInt();
		
		//resp:  [r_s, r_v, r_t, r_x]
		BigInteger s1L = (b.modPow(r_s, p).multiply(h.modPow(r_v, p))).mod(p);
		BigInteger s1R = (pComm.modPow(challenge, p).multiply(a_1)).mod(p);
		
		BigInteger s2L = (y.modPow(r_s, p).multiply(h.modPow(r_t, p))).mod(p);
		BigInteger s2R = (lComm.modPow(challenge, p).multiply(a_2)).mod(p);
		
		BigInteger s3L = (g.modPow(r_x, p).multiply(h.modPow(r_t, p))).mod(p);
		BigInteger s3R = (lComm.modPow(challenge, p).multiply(a_3)).mod(p);

		//a = [a_1, a_2, a_3, binA_0, binA_1]
		//r = [r_s, r_v, r_t, r_x, c_1, r_0, r_1]
		
		//y^s * h^t
		BigInteger s4L = h.modPow(r_0, p);
		BigInteger s4R = (binA_0.multiply(lComm.modPow(challenge.subtract(c_1), p))).mod(p);
				
		BigInteger s5L = h.modPow(r_1, p);
		BigInteger s5R = (binA_1.multiply((lComm.multiply(y.modInverse(p))).modPow(c_1, p))).mod(p);
		boolean toReturn = (s1L.equals(s1R) && s2L.equals(s2R) && s3L.equals(s3R) && s4L.equals(s4R) && s5L.equals(s5R));
		if(!toReturn) {
			System.out.println("Verifier Input = " + input);
			System.out.printf("%s		==		%s\n%s		==		%s\n%s		==		%s\n%s		==		%s\n%s		==		%s\n\n\n",s1L,(s1R), s2L,(s2R), s3L,(s3R), s4L,(s4R), s5L,(s5R));
		}
		return toReturn;
	}

}
