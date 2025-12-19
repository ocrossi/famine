dir='/tmp/test'
dir2='/tmp/test2'

rm -rf $dir $dir2

mkdir -p $dir/depth1/depth2
echo toto > $dir/file1
echo toto > $dir/depth1/file2
mkdir -p $dir2/depth1/

cp /bin/ls $dir 
cp /bin/ls $dir/depth1/depth2/
cp /bin/ls $dir2/depth1/ 


make re 

# ./Famine
