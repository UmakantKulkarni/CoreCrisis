if [ "$EUID" -ne 0 ]
	then echo "Need to run as root"
	exit
fi

echo "Launching start_core.sh"

source_dir=`pwd`
cd $OPEN5GS_PATH

./build/tests/app/5gc ./build/configs/sample.yaml &> $OPEN5GS_PATH/core.log &

cd "$source_dir"

echo "Finished launching start_core.sh"