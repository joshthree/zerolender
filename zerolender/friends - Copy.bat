@echo off

for /l %%x in (1, 1, 10) do (
	for /l %%y in (1, 1, %%x) do (
		SET /a "_blah3=%%y-1"
		start /W java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ECKeyMakerMultiSigWithFriends secp256k1 1000 %%x %%y 0.05 0.5
		start /W java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ProtocolMainECMixedMalWithComparisonMultiSigWithFriends %2 %3 %4 Account1000_0.05_0.5_%%x_%%y P%1.0_Keys1000_0.05_0.5_%%x_%%y ecEnvironment 1 P%1_!_blah3!_friend	
	)
)