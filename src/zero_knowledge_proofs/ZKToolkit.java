package zero_knowledge_proofs;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.InputMismatchException;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public abstract class ZKToolkit {
	protected static ZKPProtocol schnorr = new ECSchnorrProver();
	protected static ZKPProtocol bitProof = new ZeroKnowledgeOrProver(new ZKPProtocol[] {schnorr, schnorr});
	protected static ZKPProtocol prechosenExponentProver = new ECProofOfPrechosenExponentProver();
	private static boolean registered = false;
	public static boolean register()
	{
		if(registered)
			return false;
		registered = true;
		return (
				ZKPProtocol.registerProtocol("OR", ZeroKnowledgeOrProver.class, true) &&
				ZKPProtocol.registerProtocol("AND", ZeroKnowledgeAndProver.class, true) &&
				ZKPProtocol.registerProtocol("ECSchnorr", ECSchnorrProver.class, false) &&
				ZKPProtocol.registerProtocol("DLSchnorr", DLSchnorrProver.class, false) &&
				ZKPProtocol.registerProtocol("ECEqualLogs", ECEqualDiscreteLogsProver.class, false) && 
				ZKPProtocol.registerProtocol("PrechosenExponent", ECProofOfPrechosenExponentProver.class, false));
		
	}
	public static boolean registered()
	{
		return registered;
	}
	
	public static CryptoData ellipticExpElgamalEncrypt(BigInteger message, BigInteger ephemeralKey, CryptoData environment) 
	{
		CryptoData toReturn = null;
		CryptoData[] temp = environment.getCryptoDataArray();
		
		ECCurve c = temp[0].getECCurveData();
		ECPoint g = temp[0].getECPointData(c);
		ECPoint y = temp[1].getECPointData(c);
		
		ECPoint cipher = g.multiply(message).add(y.multiply(ephemeralKey));
		ECPoint cipherKey = g.multiply(ephemeralKey);
		
		toReturn = new CryptoDataArray(new ECPointData[] {new ECPointData(cipher), new ECPointData(cipherKey)});
		
		return toReturn;
	}
	
	public static CryptoData createEncryption(BigInteger message, CryptoData environment, SecureRandom r)
	{
		CryptoData[] e = environment.getCryptoDataArray();
		ECCurve c = e[0].getECCurveData();
		int bits = c.getOrder().bitLength();
		BigInteger ephKey = new BigInteger(bits, r);
		while(ephKey.compareTo(c.getOrder()) >= 0)
		{
			ephKey = new BigInteger(bits, r);
		}
		CryptoData cipher = ellipticExpElgamalEncrypt(message, ephKey, environment);
		
		return cipher;
	}

	public static ECPoint decryptECElgamal(CryptoData encryption, BigInteger privateKey, CryptoData environment)
	{
		CryptoData[] e = environment.getCryptoDataArray();
		ECCurve c = e[0].getECCurveData();
		
		CryptoData[] encArray = encryption.getCryptoDataArray();
		
		return encArray[0].getECPointData(c).add(encArray[1].getECPointData(c).multiply(privateKey.negate()));
	}
	
	public static CryptoData randomizeEllipticElgamal(CryptoData orig, BigInteger ephemeralKeyChange, CryptoData environment)
	{

		CryptoData[] temp = environment.getCryptoDataArray();
		
		ECCurve c = temp[0].getECCurveData();
		ECPoint g = temp[0].getECPointData(c);
		ECPoint y = temp[1].getECPointData(c);
		
		temp = orig.getCryptoDataArray();
		ECPoint origCipher = temp[0].getECPointData(c);
		ECPoint origCipherKey = temp[1].getECPointData(c);
		
		ECPoint newCipher = origCipher.add(y.multiply(ephemeralKeyChange));
		ECPoint newCipherKey = origCipherKey.add(g.multiply(ephemeralKeyChange));
		
		temp = new CryptoData[2];
		temp[0] = new ECPointData(newCipher);
		temp[1] = new ECPointData(newCipherKey);
		return new CryptoDataArray(temp);
	}
	public static boolean plaintextEqualityTest(CryptoData[] encryption1, CryptoData[] encryption2, BigInteger privateKey, ObjectInputStream[] in, ObjectOutputStream[] out, CryptoData environment, int prevParty, int nextParty, SecureRandom r) throws IOException, ClassNotFoundException, MultipleTrueProofException, NoTrueProofException, ArraySizesDoNotMatchException, CheaterException
	{
		CryptoData[] e = environment.getCryptoDataArray();
		ECCurve c = e[0].getECCurveData();
		BigInteger order = c.getOrder();
		int bitLength = order.bitLength();
		
		ECPoint[] diff = new ECPoint[2];
		
		diff[0] = encryption1[0].getECPointData(c).subtract(encryption2[0].getECPointData(c));
		diff[1] = encryption1[1].getECPointData(c).subtract(encryption2[1].getECPointData(c));
		BigInteger random;
		random = new BigInteger(bitLength, r);
		while(random.compareTo(order) >= 0)
			random = new BigInteger(bitLength, r);
		BigInteger message;
		message = new BigInteger(bitLength, r);
		while(message.compareTo(order) >= 0)
			message = new BigInteger(bitLength, r);
		ECPedersenCommitment comm = new ECPedersenCommitment(message, random, environment);
		ECPedersenCommitment[] otherComms = new ECPedersenCommitment[out.length];
		for(int i = 0; i < out.length; i++)
		{
			out[i].writeObject(comm);
			out[i].flush();
			otherComms[i] = (ECPedersenCommitment) in[i].readObject();
		}
		ECPoint[] randomized = new ECPoint[] {diff[0].multiply(message),diff[1].multiply(message)};
		CryptoData randomizedDiff = new CryptoDataArray(randomized);
		CryptoData[] otherRandomizedDiff = new CryptoDataArray[out.length];
		for(int i = 0; i < out.length; i++)
		{
			out[i].writeObject(randomizedDiff);
			out[i].flush();
		}
		CryptoData proverInput = getPrechosenExponentProverInputs(diff, randomized, comm.getCommitment(environment), message, random, r);
		CryptoData[] verifierInput = new CryptoData[out.length];
		for(int i = 0; i < out.length; i++)
		{
			otherRandomizedDiff[i] = (CryptoData) in[i].readObject();	
			ECPoint[] otherRandomized = new ECPoint[2];
			CryptoData[] oRD = otherRandomizedDiff[i].getCryptoDataArray();
			otherRandomized[0] = oRD[0].getECPointData(c);
			otherRandomized[1] = oRD[1].getECPointData(c);
			verifierInput[i] = getPrechosenExponentVerifierInputs(diff, otherRandomized, otherComms[i].getCommitment(environment));
			randomized[0] = randomized[0].add(otherRandomized[0]);
			randomized[1] = randomized[1].add(otherRandomized[1]);
		}
		
		BigInteger[] challenge = new BigInteger[2];
		challenge[0] = new BigInteger(bitLength - 1, r);
		challenge[1] = new BigInteger(bitLength, r);
		while(challenge[1].compareTo(order) >= 0)
			challenge[1] = new BigInteger(bitLength, r);
		ECPedersenCommitment myCmt = new ECPedersenCommitment(challenge[0], challenge[1], environment);
		if(!prechosenExponentProver.parallelZKProve(proverInput, verifierInput[0], environment, in[0], out[0], myCmt, environment, challenge, null))
			throw new CheaterException();
		CryptoData partiallyDecrypted;		
		
		if(prevParty != -1)
		{
			partiallyDecrypted = (CryptoData) in[prevParty].readObject();
			randomized[0] = decryptECElgamal(partiallyDecrypted, privateKey, environment);

		}
		else
		{
			randomized[0] = decryptECElgamal(new CryptoDataArray(randomized), privateKey, environment);
			partiallyDecrypted = new CryptoDataArray(randomized);
		}
		
		boolean equal;
		if(nextParty != -1)
		{
			out[nextParty].writeObject(new CryptoDataArray(randomized));
			out[nextParty].flush();
			equal = in[nextParty].readBoolean();
		}
		else 
		{
			equal = randomized[0].isInfinity();
		}
		if(prevParty != -1){
			out[prevParty].writeBoolean(equal);
			out[prevParty].flush();
		}
		return equal;
	}
	
	private static CryptoData getPrechosenExponentVerifierInputs(ECPoint[] base, ECPoint[] exponentiatedBase,
			ECPoint commitment) {
		CryptoData[] inputs = new CryptoData[3];
		inputs[0] = new ECPointData(base[0].add(base[1]));
		inputs[1] = new ECPointData(exponentiatedBase[0].add(exponentiatedBase[1]));
		inputs[2] = new ECPointData(commitment);

		return new CryptoDataArray(inputs);
	}
	private static CryptoData getPrechosenExponentProverInputs(ECPoint[] base, ECPoint[] exponentiatedBase,
			ECPoint commitment, BigInteger exponent, BigInteger key, SecureRandom r) {
		BigInteger order = base[0].getCurve().getOrder();
		CryptoData[] inputs = new CryptoData[7];
		inputs[0] = new ECPointData(base[0].add(base[1]));
		inputs[1] = new ECPointData(exponentiatedBase[0].add(exponentiatedBase[1]));
		inputs[2] = new ECPointData(commitment);
		BigInteger random;
		do {
			random = new BigInteger(order.bitLength(), r);
		} while(random.compareTo(order) >= 0);
		inputs[3] = new BigIntData(random);
		do {
			random = new BigInteger(order.bitLength(), r);
		} while(random.compareTo(order) >= 0);
		inputs[4] = new BigIntData(random);
		inputs[5] = new BigIntData(exponent);
		inputs[6] = new BigIntData(key);
		return new CryptoDataArray(inputs);
	}
	
	public static CryptoData[] rangeProofFiatShamirConstruction(BigInteger m, BigInteger key, BigInteger min, BigInteger max, CryptoData environment, SecureRandom rand)
	{
		
		ECCurve c;
		ECPoint g;
		ECPoint h;
		BigInteger order;
		
		{
			CryptoData[] e = environment.getCryptoDataArray();
			c = e[0].getECCurveData();
			g = e[0].getECPointData(c);
			h = e[1].getECPointData(c);
			order = c.getOrder();
		}
		CryptoData temp = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, h)});
		CryptoData revEnv = new CryptoDataArray(new CryptoData[] {temp, temp});
		CryptoData[] toReturn = new CryptoData[2];
		BigInteger diff = max.subtract(min);
		int numBits = diff.bitLength();
		BigInteger mag = (BigInteger.ONE.shiftLeft(numBits)).subtract(BigInteger.ONE);
		
		
		
		
		if((mag.equals(diff))) {
			ECPedersenOwnedBitwiseCommitment bits = VarianceToolkit.ecConvertToBits(m.subtract(min), key, numBits, environment, rand);
			ECPedersenCommitment[] comms = bits.getComm();
			BigInteger[] keys = bits.getKeys();
			CryptoData[] bitComms = new CryptoData[numBits];
			
			CryptoData[] proofTranscripts = new CryptoData[numBits];
		
			for(int i = 0; i < numBits; i++)
			{
				ECPoint commitment = comms[i].getCommitment(environment);
				ECPoint commitmentMinusOne = commitment.subtract(g);
				bitComms[i] = new ECPointData(comms[i].getCommitment(environment));
				CryptoData[] challenges = new CryptoData[2];
				CryptoData[] outerPublicInputs = new CryptoData[2];
				CryptoData[] outerPrivateInputs = new CryptoData[3];
				if(bits.getMessage().testBit(i)) {
//					System.out.println("True:  ");
					challenges[0] = new BigIntData(new BigInteger(order.bitLength()-1, rand));
					challenges[1] = new BigIntData(BigInteger.ZERO);
					
					outerPublicInputs[0] = new CryptoDataArray(new CryptoData[] {bitComms[i]});
					outerPublicInputs[1] = new CryptoDataArray(new CryptoData[] {new ECPointData(commitmentMinusOne)});
					
					outerPrivateInputs[0] = new CryptoDataArray(new CryptoData[] {new BigIntData(random(order, rand))});
					outerPrivateInputs[1] = new CryptoDataArray(new BigInteger[] {random(order, rand), keys[i]});
					outerPrivateInputs[2] = new CryptoDataArray(challenges);
					
					try {
						proofTranscripts[i] = new CryptoDataArray(bitProof.proveFiatShamir(new CryptoDataArray(outerPublicInputs), new CryptoDataArray(outerPrivateInputs), revEnv));
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
							| ArraySizesDoNotMatchException e) {
						e.printStackTrace();
					}
				}
				else {
//					System.out.println("False");
					challenges[0] = new BigIntData(BigInteger.ZERO);
					challenges[1] = new BigIntData(new BigInteger(order.bitLength()-1, rand));
					
					outerPublicInputs[0] = new CryptoDataArray(new CryptoData[] {bitComms[i]});
					outerPublicInputs[1] = new CryptoDataArray(new CryptoData[] {new ECPointData(commitmentMinusOne)});
					
					outerPrivateInputs[0] = new CryptoDataArray(new BigInteger[] {random(order, rand), keys[i]});
					outerPrivateInputs[1] = new CryptoDataArray(new CryptoData[] {new BigIntData(random(order, rand))});
					outerPrivateInputs[2] = new CryptoDataArray(challenges);
					
					try {
						proofTranscripts[i] = new CryptoDataArray(bitProof.proveFiatShamir(new CryptoDataArray(outerPublicInputs), new CryptoDataArray(outerPrivateInputs), revEnv));
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
							| ArraySizesDoNotMatchException e) {
						e.printStackTrace();
					}
				}
				
			}
			toReturn[0] = new CryptoDataArray(bitComms);
			toReturn[1] = new CryptoDataArray(proofTranscripts);
		}
		else {
			ECPedersenOwnedBitwiseCommitment bits = VarianceToolkit.ecConvertToBits(m.subtract(min), key, numBits, environment, rand);
			ECPedersenCommitment[] comms = bits.getComm();
			BigInteger[] keys = bits.getKeys();
			CryptoData[] bitComms = new CryptoData[numBits];
			
			CryptoData[] proofTranscripts = new CryptoData[numBits];
			CryptoData[][] toReturnInner = new CryptoData[2][2];
			for(int i = 0; i < numBits; i++)
			{
				ECPoint commitment = comms[i].getCommitment(environment);
				ECPoint commitmentMinusOne = commitment.subtract(g);
				bitComms[i] = new ECPointData(comms[i].getCommitment(environment));
				CryptoData[] challenges = new CryptoData[2];
				CryptoData[] outerPublicInputs = new CryptoData[2];
				CryptoData[] outerPrivateInputs = new CryptoData[3];
				
				if(bits.getMessage().testBit(i)) {
					challenges[0] = new BigIntData(random(order, rand));
					challenges[1] = new BigIntData(BigInteger.ZERO);
					
					outerPublicInputs[0] = new CryptoDataArray(new CryptoData[] {bitComms[i]});
					outerPublicInputs[1] = new CryptoDataArray(new CryptoData[] {new ECPointData(commitmentMinusOne)});
					
					outerPrivateInputs[0] = new CryptoDataArray(new CryptoData[] {new BigIntData(random(order, rand))});
					outerPrivateInputs[1] = new CryptoDataArray(new BigInteger[] {random(order, rand), keys[i]});
					outerPrivateInputs[2] = new CryptoDataArray(challenges);
					
					try {
						proofTranscripts[i] = new CryptoDataArray(bitProof.proveFiatShamir(new CryptoDataArray(outerPublicInputs), new CryptoDataArray(outerPrivateInputs), revEnv));
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
							| ArraySizesDoNotMatchException e) {
						e.printStackTrace();
					}
				}
				else {
					challenges[0] = new BigIntData(BigInteger.ZERO);
					challenges[1] = new BigIntData(random(order, rand));
					
					outerPublicInputs[0] = new CryptoDataArray(new CryptoData[] {bitComms[i]});
					outerPublicInputs[1] = new CryptoDataArray(new CryptoData[] {new ECPointData(commitmentMinusOne)});
					
					outerPrivateInputs[0] = new CryptoDataArray(new BigInteger[] {(random(order, rand)), keys[i]});
					outerPrivateInputs[1] = new CryptoDataArray(new BigInteger[] {random(order, rand)});
					outerPrivateInputs[2] = new CryptoDataArray(challenges);
					
					try {
						proofTranscripts[i] = new CryptoDataArray(bitProof.proveFiatShamir(new CryptoDataArray(outerPublicInputs), new CryptoDataArray(outerPrivateInputs), revEnv));
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
							| ArraySizesDoNotMatchException e) {
						e.printStackTrace();
					}
				}
				
			}
			toReturnInner[0][0] = new CryptoDataArray(bitComms);
			toReturnInner[1][0] = new CryptoDataArray(proofTranscripts);
			
			bits = VarianceToolkit.ecConvertToBits(m.add((max.subtract(min)).subtract(mag)), key, numBits, environment, rand);
			comms = bits.getComm();
			keys = bits.getKeys();
			bitComms = new CryptoData[numBits];
			
			proofTranscripts = new CryptoData[numBits];
			for(int i = 0; i < numBits; i++)
			{
				ECPoint commitment = comms[i].getCommitment(environment);
				ECPoint commitmentMinusOne = commitment.subtract(g);
				bitComms[i] = new ECPointData(comms[i].getCommitment(environment));
				CryptoData[] challenges = new CryptoData[2];
				CryptoData[] outerPublicInputs = new CryptoData[2];
				CryptoData[] outerPrivateInputs = new CryptoData[3];
				
				if(bits.getMessage().testBit(i)) {
					challenges[0] = new BigIntData(random(order, rand));
					challenges[1] = new BigIntData(BigInteger.ZERO);
					
					outerPublicInputs[0] = new CryptoDataArray(new CryptoData[] {bitComms[i]});
					outerPublicInputs[1] = new CryptoDataArray(new CryptoData[] {new ECPointData(commitmentMinusOne)});
					
					outerPrivateInputs[0] = new CryptoDataArray(new CryptoData[] {new BigIntData(random(order, rand))});
					outerPrivateInputs[1] = new CryptoDataArray(new BigInteger[] {random(order, rand), keys[i]});
					outerPrivateInputs[2] = new CryptoDataArray(challenges);
					
					try {
						proofTranscripts[i] = new CryptoDataArray(bitProof.proveFiatShamir(new CryptoDataArray(outerPublicInputs), new CryptoDataArray(outerPrivateInputs), revEnv));
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
							| ArraySizesDoNotMatchException e) {
						e.printStackTrace();
					}
				}
				else {
					challenges[0] = new BigIntData(BigInteger.ZERO);
					challenges[1] = new BigIntData(random(order, rand));
					
					outerPublicInputs[0] = new CryptoDataArray(new CryptoData[] {bitComms[i]});
					outerPublicInputs[1] = new CryptoDataArray(new CryptoData[] {new ECPointData(commitmentMinusOne)});
					
					outerPrivateInputs[0] = new CryptoDataArray(new BigInteger[] {random(order, rand), keys[i]});
					outerPrivateInputs[1] = new CryptoDataArray(new BigInteger[] {random(order, rand)});
					outerPrivateInputs[2] = new CryptoDataArray(challenges);
					
					try {
						proofTranscripts[i] = new CryptoDataArray(bitProof.proveFiatShamir(new CryptoDataArray(outerPublicInputs), new CryptoDataArray(outerPrivateInputs), revEnv));
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
							| ArraySizesDoNotMatchException e) {
						e.printStackTrace();
					}
				}
				
			}
			toReturnInner[0][1] = new CryptoDataArray(bitComms);
			toReturnInner[1][1] = new CryptoDataArray(proofTranscripts);
			toReturn[0] = new CryptoDataArray(toReturnInner[0]);
			toReturn[1] = new CryptoDataArray(toReturnInner[1]);
		}
		
		return toReturn;
	}
	private static final BigInteger TWO = BigInteger.valueOf(2);
	public static boolean rangeProofFiatShamirVerify(CryptoData commitment, CryptoData[] transcript, BigInteger min, BigInteger max, CryptoData environment) {
		ECCurve c;
		ECPoint g;
		ECPoint h;
//		BigInteger order;
		
		{
			CryptoData[] e = environment.getCryptoDataArray();
			c = e[0].getECCurveData();
			g = e[0].getECPointData(c);
			h = e[1].getECPointData(c);
//			order = c.getOrder();
		}
		CryptoData temp = new CryptoDataArray(new CryptoData[] {new ECCurveData(c, h)});
		CryptoData revEnv = new CryptoDataArray(new CryptoData[] {temp, temp});
		BigInteger diff = max.subtract(min);
		int numBits = diff.bitLength();
		BigInteger mag = (BigInteger.ONE.shiftLeft(numBits)).subtract(BigInteger.ONE);
		 
		if((mag.equals(diff))) {
			CryptoData[] bits = transcript[0].getCryptoDataArray();
			CryptoData[] proofTranscripts = transcript[1].getCryptoDataArray();
			ECPoint shiftProd = c.getInfinity();
			for(int i = bits.length - 1; i >= 0; i--){
				CryptoData[] bitTranscript = proofTranscripts[i].getCryptoDataArray();
				ECPoint p = bits[i].getECPointData(c);
				shiftProd = shiftProd.multiply(TWO).add(p);
				CryptoData publicInputs = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(new CryptoData[] {bits[i]}), new CryptoDataArray(new CryptoData[]{new ECPointData(p.subtract(g))})});
				try {
					if(!bitProof.verifyFiatShamir(publicInputs, bitTranscript[0], bitTranscript[1], revEnv)) {
						return false;
					}
				} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
						| ArraySizesDoNotMatchException e) {
					System.out.println("Bad Proof bit " + i);
					return false;
				}
			}
			ECPoint commDiff = (commitment.getECPointData(c).subtract(g.multiply(min)));
			if(!commDiff.equals(shiftProd)) {
				System.out.println("Bad bits!");
				return false;
			}
		}
		else {
			CryptoData[] bits = transcript[0].getCryptoDataArray()[0].getCryptoDataArray();
//			System.out.println(transcript[0].getCryptoDataArray()[0].getCryptoDataArray());
			CryptoData[] proofTranscripts = transcript[1].getCryptoDataArray()[0].getCryptoDataArray();
			ECPoint shiftProd = c.getInfinity();
			for(int i = bits.length - 1; i >= 0; i--){
				CryptoData[] bitTranscript = proofTranscripts[i].getCryptoDataArray();
				ECPoint p = bits[i].getECPointData(c);
				shiftProd = shiftProd.multiply(TWO).add(p);
				CryptoData publicInputs = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(new CryptoData[] {bits[i]}), new CryptoDataArray(new CryptoData[]{new ECPointData(p.subtract(g))})});
				try {
					if(!bitProof.verifyFiatShamir(publicInputs, bitTranscript[0], bitTranscript[1], revEnv)) {
						return false;
					}
				} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
						| ArraySizesDoNotMatchException e) {
					System.out.println("Bad Proof bit " + i);
					return false;
				}
			}
			ECPoint commDiff = (commitment.getECPointData(c).subtract(g.multiply(min)));
			if(!commDiff.equals(shiftProd)) {
				System.out.println("Bad bits!");
				return false; 
			}
			bits = transcript[0].getCryptoDataArray()[1].getCryptoDataArray();
			proofTranscripts = transcript[1].getCryptoDataArray()[1].getCryptoDataArray();
			//System.out.println(proofTranscripts[0].getCryptoDataArray());
			shiftProd = c.getInfinity();
			for(int i = bits.length - 1; i >= 0; i--){

				CryptoData[] bitTranscript = proofTranscripts[i].getCryptoDataArray();
				ECPoint p = bits[i].getECPointData(c);
				shiftProd = shiftProd.multiply(TWO).add(p);
				CryptoData publicInputs = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(new CryptoData[] {bits[i]}), new CryptoDataArray(new CryptoData[]{new ECPointData(p.subtract(g))})});
				try {
					if(!bitProof.verifyFiatShamir(publicInputs, bitTranscript[0], bitTranscript[1], revEnv)) {
						return false;
					}
				} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
						| ArraySizesDoNotMatchException e) {
					System.out.println("Bad Proof bit " + i);
					return false;
				}
			}
			commDiff = (commitment.getECPointData(c).add(g.multiply(max.subtract(min).subtract(mag))));
			if(!commDiff.equals(shiftProd)) {
				System.out.println("Bad bits!");
				return false;
			}
		}
		return true;
	}
	
	public static BigInteger random(BigInteger max, SecureRandom r) {
		BigInteger toReturn;
		do {
			toReturn = new BigInteger(max.bitLength(), r);
			
		}while(toReturn.compareTo(max) >= 0);
		return toReturn;
	}
	public static ECPoint[] multiCommitment(BigInteger m, BigInteger[] keys, CryptoData environment) {
		CryptoData[] e = environment.getCryptoDataArray();
		ECCurve c = e[0].getECCurveData();
		ECPoint g = e[0].getECPointData(c);
		ECPoint h = e[1].getECPointData(c);
		BigInteger order = c.getOrder();
		
		ECPoint[] toReturn = new ECPoint[keys.length];
		BigInteger dividend = m;
		
		for(int i = 0; i < keys.length; i++) {
			toReturn[i] = g.multiply(dividend.mod(order)).add(h.multiply(keys[i]));		
			dividend = dividend.divide(order);
			
			if(dividend.equals(BigInteger.ZERO)) {
				i++;
				while(i < keys.length) {
					toReturn[i] = h.multiply(keys[i]);
					i++;
				}
			}
			if(!dividend.equals(BigInteger.ZERO)) {
				throw new InputMismatchException("Too few keys");
			}
		}
		return toReturn;
	}
}