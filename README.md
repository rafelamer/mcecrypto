# Implementation of the RSA and ECC algorithm for educational purposes

I'm teaching a course about mathematics and computer science at the Technical University of Catalonia BarcelonaTech and I started a project about multiprecision arithmetic of integers: how to store arbitrarily  large integers  in the memory of a computer and how to add, subtract or multiply them. As the project evolved over time, I was interested in cryptography and the RSA and ECC algorithms.

One of the goals of the project was that my students could study the code and that this was as simple as possible, so that I discarded complex libraries like OpenSSL or GNU GMP. Then, I wrote my own library for educational purposes. I'm not a cryptographer and I'm sure that it has bugs and should not be used in contexts that need cryptographically secure implementation. Use OpenSSL instead.

To complement the RSA and ECC algorithms, I needed some symmetric cryptographic algorithms, so I downloaded different implementations from [https://github.com/Rupan/rsa](https://github.com/Rupan/rsa), [http://www.cs.technion.ac.il/~biham/Reports/Tiger/](http://www.cs.technion.ac.il/~biham/Reports/Tiger/) and [https://www.nongnu.org/oath-toolkit/](OATH Toolkit).

Thanks to Eli Biham and the OATH Toolkit team.

## Getting Started

### Prerequisites

To compile and install the library you need a Unix-like computer with a compiler (GCC) and the libraries zlib and argon2. I have tested the installation in Linux.

### Installing

To install the library, you have to run the following commands
```
~$ git clone https://github.com/rafelamer/mcecrypto.git
~$ cd mcecrypto
~$ make
~$ sudo make install
```

## Authors

* **Rafel Amer**
ESEIAAT
Technical University of Catalonia BarcelonaTech
rafel.amer@upc.edu


## License

This project is licensed under the GNU Lesser General Public License.  See the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

I want to acknowledge

- The OATH Toolkit team
- Eli Biham

I have used some of their code in the project.

And also the authors of the excellent books

- Handbook of Applied Cryptography
Alfred J. Menezes, Paul C. van Oorschot and   Scott A. Vanstone
CRC Press; 1 edition
1996
ISBN: 0849385237

- Applied Cryptography: Protocols, Algorithms and Source Code in C
Bruce Schneier
Wiley; 1 edition
2015
ISBN: 1119096723

- Introduction to Modern Cryptography
Jonathan Katz and Yehuda Lindell
Chapman and Hall/CRC; 2 edition
2014
ISBN: 1466570261

- Programming Projects in C for Students of
Engineering, Science and Mathematics
Rouben Rostamian
SIAM
Computational Science & Engineering (2014)
ISBN 978-1-611973-49-5
