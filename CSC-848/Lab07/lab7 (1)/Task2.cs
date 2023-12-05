using System;
using System.IO;
using System.Text;

class Program
{
    static void Main(string[] args){
        File.WriteAllText(@"c:\temp\abc.txt","abc");
    }
}