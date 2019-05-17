WORKDIR="/tmp/castauth"
exec_test(){
	eval "$1"
	if [ $? -eq 0 ];
	then
		echo "[success]"
	else
		echo "[error]"
	fi
}

mkdir -p $WORKDIR
rm -rf $WORKDIR/*

echo "> Hardware Id"
exec_test "castauth hwid"
echo "> Generate RSA key usning SW"
exec_test "openssl genrsa -out $WORKDIR/private.key 2048"
echo "> Wrap key to a black key"
exec_test  "castauth wrap $WORKDIR/private.key $WORKDIR/black.key"
echo "> Sign using black key"
exec_test  "castauth sign test $WORKDIR/private.key $WORKDIR/black.key"
echo "> Export to black blob"
exec_test  "castauth export $WORKDIR/black.key $WORKDIR/blob.key"
echo "> Import blob to to black key"
exec_test "castauth import $WORKDIR/blob.key $WORKDIR/black2.key"
echo "> Sign using imported black key"
exec_test "castauth sign test $WORKDIR/private.key $WORKDIR/black2.key"
echo "> Wrap model key"
exec_test "castauth wrap ../assets/model.key $WORKDIR/model.key.black"
echo "> Export model key"
exec_test "castauth export $WORKDIR/model.key.black $WORKDIR/model.key.blob"
export CAST_MODEL_PRIVKEY="$WORKDIR/model.key.blob"
echo "> Generate a device key and certificate"
exec_test "castauth indiv $WORKDIR/device.crt $WORKDIR/device.key"
echo "> Sign using device key and verify using device cert"
exec_test "castauth cert test $WORKDIR/device.crt $WORKDIR/device.key"
echo "> Generate RSA key using HW"
exec_test  "castauth gen $WORKDIR/rsa.key"
echo "> Get Manufacturing Protection public key"
exec_test  "castauth mppubk $WORKDIR/mppub.key"

echo "> Cleaning"
rm -rf $WORKDIR

