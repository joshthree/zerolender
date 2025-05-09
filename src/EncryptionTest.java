import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class EncryptionTest {
	public static void main(String[] args)
	{
		BigInteger privateKey = BigInteger.valueOf(1234567890);
		
		ECPoint g = ECNamedCurveTable.getParameterSpec("secp256k1").getG();
		
		ECCurve c = g.getCurve();
		ECPoint inf = c.getInfinity();
		ECPoint publicKey = g.multiply(privateKey);
		
		SecureRandom r = new SecureRandom();
		
		CryptoData environment = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, g), new ECPointData(publicKey)});
		
		CryptoData encryption = ZKToolkit.createEncryption(BigInteger.ZERO, environment, r);
		encryption = ZKToolkit.randomizeEllipticElgamal(encryption, BigInteger.valueOf(987654321), environment);
		ECPoint result = ZKToolkit.decryptECElgamal(encryption, privateKey, environment);
		System.out.println(result);
	}	
}
