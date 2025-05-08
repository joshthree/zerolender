package proverTest;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ECEqualDiscreteLogsProver;
import zero_knowledge_proofs.ECEqualDiscreteLogsVerifier;
import zero_knowledge_proofs.ZKPProver;
import zero_knowledge_proofs.ZKPVerifier;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class TestEqualLogTest {
	public static void main(String[] args)
	{
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		ECCurve c = g.getCurve();
		ECPoint h = g.multiply(BigInteger.valueOf(1234567890));
		BigInteger x = BigInteger.valueOf(987654321);
		ECPoint y1 = g.multiply(x);
		ECPoint y2 = h.multiply(x);
		
		SecureRandom random = new SecureRandom();
		
		CryptoData pInputs = new CryptoDataArray(new CryptoData[] {new ECPointData(y1),new ECPointData(y2),new BigIntData(new BigInteger(255, random)),new BigIntData(x)});
		CryptoData vInputs = new CryptoDataArray(new CryptoData[] {new ECPointData(y1),new ECPointData(y2)});
		
		CryptoData environment = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, g), new ECPointData(h)});
		
		ZKPProver prover = new ECEqualDiscreteLogsProver();
		ZKPVerifier verifier= new ECEqualDiscreteLogsVerifier();
		
		CryptoData initialComm = prover.prove(pInputs, environment, in, out)
	}
}
