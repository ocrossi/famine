dir='/tmp/test'

rm -rf $dir

mkdir -p $dir/depth1/depth2

echo toto > $dir/file1
echo toto > $dir/depth1/file2

cp /bin/ls $dir 
cp /bin/ls $dir/depth1/depth2/

make re 

./Famine
