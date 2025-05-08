package zero_knowledge_proofs;

import java.math.BigInteger;

import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class DLSchnorrProver extends ZKPProtocol {
	 
	 
	 //input format:  [y, r, x]

	@Override
	public CryptoData initialComm(CryptoData input, CryptoData environment) {
		BigInteger[] data = new BigInteger[1];
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] i = input.getCryptoDataArray();
		BigInteger p = e[0].getBigInt();
		BigInteger g = e[1].getBigInt();
		BigInteger r = i[1].getBigInt();
		data[0] = g.modPow(r, p);

		CryptoData toReturn = new CryptoDataArray(data);
		return toReturn;
	}

	//input format [y, z]
	@Override
	public CryptoData initialCommSim(CryptoData input, BigInteger challenge, CryptoData environment) {
		BigInteger[] data = new BigInteger[1];
		CryptoData[] i = input.getCryptoDataArray();
		CryptoData[] e = environment.getCryptoDataArray();		//(y, z) 
		BigInteger y = i[0].getBigInt();
		BigInteger z = i[1].getBigInt();
		BigInteger g = e[1].getBigInt();
		BigInteger p = e[0].getBigInt();
		//a = g^z * y^(-c)
		data[0] = g.modPow(z, p).multiply(y.modPow(challenge.negate(), p)).mod(p);

		
		CryptoData toReturn = new CryptoDataArray(data);
		return toReturn;
	}

	@Override
	public CryptoData calcResponse(CryptoData input, BigInteger challenge, CryptoData environment) {
		BigInteger[] array = new BigInteger[1];
		CryptoData[] i = input.getCryptoDataArray();
		CryptoData[] e = environment.getCryptoDataArray();

		BigInteger p = e[0].getBigInt();
		BigInteger x = i[2].getBigInt();
		BigInteger r = i[1].getBigInt();
		
		array[0] = (r.add(x.multiply(challenge))).mod(p.subtract(BigInteger.ONE));
		//System.out.printf("P:\t%s ?= %s\n", ((i[1].modPow(challenge, e[1]).multiply(e[0].modPow(i[2], e[1]))).mod(e[1])), e[0].modPow(array[0], e[1]));
		
		//System.out.printf("P:\tg = %s\nP:\th = %s\nP:\tp = %s\nP:\tr = %s\nP:\tx = %s\nP:\ty = %s\nP:\tz = %s\nP:\tc = %s\n",e[0],e[1],e[1],i[2],i[0],i[1], array[0], challenge);
		CryptoData toReturn = new CryptoDataArray(array);
		return toReturn;
	}

	@Override
	public CryptoData simulatorGetResponse(CryptoData input) {
		CryptoData[] in = input.getCryptoDataArray();
		BigInteger[] out = new BigInteger[1];
		out[0] = in[1].getBigInt();
		return new CryptoDataArray(out);
	}


	@Override
	public CryptoData simulatorGetResponse(CryptoData publicInput, CryptoData secrets) {
		CryptoData[] in = secrets.getCryptoDataArray();
		BigInteger[] out = new BigInteger[1];
		out[0] = in[0].getBigInt();
		return new CryptoDataArray(out);
	}
	//input format:  [y]

	@Override
	public boolean verifyResponse(CryptoData input, CryptoData initial_comm, CryptoData response, BigInteger challenge,
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

	@Override
	public CryptoData initialComm(CryptoData publicInput, CryptoData secrets, CryptoData environment)
			throws MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException {
		
		BigInteger[] data = new BigInteger[1];
		CryptoData[] e = environment.getCryptoDataArray();
		CryptoData[] i = secrets.getCryptoDataArray();
		BigInteger p = e[0].getBigInt();
		BigInteger g = e[1].getBigInt();
		BigInteger r = i[0].getBigInt();
		data[0] = g.modPow(r, p);

		CryptoData toReturn = new CryptoDataArray(data);
		return toReturn;
	}

	@Override
	public CryptoData initialCommSim(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment)
					throws MultipleTrueProofException, ArraySizesDoNotMatchException, NoTrueProofException {
		BigInteger[] data = new BigInteger[1];
		CryptoData[] pI = publicInput.getCryptoDataArray();
		CryptoData[] s = secrets.getCryptoDataArray();
		CryptoData[] e = environment.getCryptoDataArray();		//(y, z) 
		BigInteger y = s[0].getBigInt();
		BigInteger z = pI[0].getBigInt();
		BigInteger g = e[1].getBigInt();
		BigInteger p = e[0].getBigInt();
		//a = g^z * y^(-c)
		data[0] = g.modPow(z, p).multiply(y.modPow(challenge.negate(), p)).mod(p);

		
		CryptoData toReturn = new CryptoDataArray(data);
		return toReturn;
	}

	@Override
	public CryptoData calcResponse(CryptoData publicInput, CryptoData secrets, BigInteger challenge,
			CryptoData environment) throws NoTrueProofException, MultipleTrueProofException {
			BigInteger[] array = new BigInteger[1];
			CryptoData[] e = environment.getCryptoDataArray();

			CryptoData[] s = secrets.getCryptoDataArray();
			BigInteger p = e[0].getBigInt();
			BigInteger x = s[1].getBigInt();
			BigInteger r = s[0].getBigInt();
			
			array[0] = (r.add(x.multiply(challenge))).mod(p.subtract(BigInteger.ONE));
			//System.out.printf("P:\t%s ?= %s\n", ((i[1].modPow(challenge, e[1]).multiply(e[0].modPow(i[2], e[1]))).mod(e[1])), e[0].modPow(array[0], e[1]));
			
			//System.out.printf("P:\tg = %s\nP:\th = %s\nP:\tp = %s\nP:\tr = %s\nP:\tx = %s\nP:\ty = %s\nP:\tz = %s\nP:\tc = %s\n",e[0],e[1],e[1],i[2],i[0],i[1], array[0], challenge);
			CryptoData toReturn = new CryptoDataArray(array);
			return toReturn;
	}

}
