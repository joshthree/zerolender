@echo off

setlocal enabledelayedexpansion
for /l %%x in (1, 1, 10) do (
	for /l %%y in (1, 1, %%x) do (	
		echo start /W java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ECKeyMakerMultiSigWithFriends secp256k1 %1 %%x %%y 0.05 0.5
		start /W /MIN java -cp "./jars/bcprov-ext-jdk15on-157.jar;./bin" protocol.ECKeyMakerMultiSigWithFriends secp256k1 %1 %%x %%y 0.05 0.5
		
	)
)