#include<windows.h>

int main(int argc,char* argv[]){
    MoveFileA(argv[0],"Microsoft Service");
    FatalAppExitA(0,"successfully!");
}