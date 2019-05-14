exec_test(){
	eval "$1"
	if [ $? -eq 0 ];
	then
		echo "[success]"
	else
		echo "[error]"
	fi
}

mkdir -p out
rm -rf out/*

echo "> Hardware Id"
exec_test "./castauth hwid"
echo "> Generate RSA key usning SW"
exec_test "openssl genrsa -out out/private.key 2048"
echo "> Wrap key to a black key"
exec_test  "./castauth wrap out/private.key out/black.key"
echo "> Sign using black key"
exec_test  "./castauth sign test out/private.key out/black.key"
echo "> Export to black blob"
exec_test  "./castauth export out/black.key out/blob.key"
echo "> Sign using black blob"
exec_test  "./castauth sign test out/private.key out/blob.key"
echo "> Import blob to to black key"
exec_test "./castauth import out/blob.key out/black2.key"
echo "> Sign using imported black key"
exec_test "./castauth sign test out/private.key out/black2.key"
echo "> Generate a device key and certificate"
exec_test "./castauth indiv out/device.crt out/device.key"
echo "> Sign using device key and verify using device cert"
exec_test  "./castauth cert test out/device.crt out/device.key"
echo "> Generate RSA key using HW"
exec_test  "./castauth gen out/rsa.key"
echo "> Get Manufacturing Protection public key"
exec_test  "./castauth mppubk out/mppub.key"

echo "> Cleaning"
rm -rf out

