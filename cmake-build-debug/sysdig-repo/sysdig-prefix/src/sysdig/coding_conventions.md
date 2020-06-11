0 Introduction
------

Sysdig strives for a consistent high quality code base and uses the conventions 
below.  If you are going to commit code that doesn't follow them, then you put the
work on us. :-(.

If you use vim or emacs, you can put a custom configuration file in the base
directory of sysdig in order to follow the conventions.

Also, note that the conventions in this file apply **strictly to the userspace** part 
of sysdig. For the kernel code, you should refer to 
https://www.kernel.org/doc/html/latest/process/coding-style.html
and always run checkpatch.pl from the kernel tree before submitting pull requests.

Thanks for your attention and time.

1 Curly Braces
------

Every curly brace ("{" and "}") should go on its own line.

Example:

    if(a == 0)
    {
      b = 1;
    }

2 If and for statements
------

Every `if` and `for` statement should have the curly braces.

Example:

    if(a == 0)
    {
      b = 1;
    }

and not

    if(a == 0) 
      b = 1;

3 Whitespace usage
------

Spaces are used in the following way:

    int32_t foo(int32_t a, int32_t b)
    {
      for(j = 0; j < 10; j++)
      {
        foo(a, b);
      }
    }

Note that:

 * in a function declaration, there is no space between the function name and the "(".
 * in a function declaration, there is no space between the "(" and the first parameter.
 * in a statement (e.g `for`, `while`...), there is no space between the "for" and the "(".
 * in a statement (e.g `for`), there is no space between the "(" and the variable name.
 * in a function call, there is no space between the function name and the "(".
 * in a function call, there is no space between the "(" and the first parameter.
 * "," and ";" work like in English: there should be a space after them.

4 Primitive types
------

For portability reasons, please use the standard C99 types instead of the native C types
like `int` and `long`. C99 types types will be available in all the user level sysdig 
source files:

Example:

    int32_t foo;

5 Commenting Style
------

Comments should be in the C++ style so we can use `/* */` to quickly remove 
portions of code during development.

Example:

    // this is a comment

6 Commenting Content
------

Code comments work in the following 2-level way:

 * A three-line comment should document what the code does and give higher level explanations.
 * A one line comment should detail single code lines or explain specific actions.

Example:

    //
    // Swap two variables
    //
    int a = 1, b = 2, t;

    // make a copy of a
    t = a;

    // perform the swap
    a = b;
    b = t;

7 Class variables
------

In order to know whether a variable belongs to a `class` or a `function` we start member variables with "`m_`".

Example:

    public int32_t m_counter;

8 Global variables
------

Similarly, in order to know whether the variable is global or not, we start
globals with "`g_`".

Example:

    int g_nplugins;

9 Capitalization
------

The naming convention is camel-cased "Unix" style, i.e. always lower case. Words are separated by underscores.

Example:

    int32_t g_global_bean_counter;

    int32_t count_beans();

and not,

    int32_t GlobalBeanCounter;

10 Packed Structures
-------
Packed structures should use the GCC and MSVC-style supported `pragma`:

    #pragma pack(push,1)
    struct frame_control
    {
        struct fields....
    };
    #pragma pack(pop)

11 OS-specific macros
-------

There's an online wiki which enumerates the different macros for compilers, operating systems, and architectures.
It's available at [http://sourceforge.net/p/predef/wiki/Home/](http://sourceforge.net/p/predef/wiki/Home/). Generally speaking we use the operating system page: [http://sourceforge.net/p/predef/wiki/OperatingSystems/](http://sourceforge.net/p/predef/wiki/OperatingSystems/).
	
12 64-bit constants
-------

Put an "LL" at the end of your 64 bit constants. Without the LL, on some platforms the compiler tries to interpret the constant on the right hand side 
as a long integer instead of a long long and in some platform this generate an error at building time.

Example:

    x=0X00FF00000000000LL

13 Class Declaration 
-------

Class declarations follow the following sequence

  1. contructors and desctuctor
  1. public functions
  1. public data
  1. private functions
  1. private data
  1. friend declarations 

Example:

    class foo
    {
    public:
      foo();
      ~foo();

      int32_t lonli();	
      int32_t m_val;

    private:
      int32_t temustra();	
      int32_t m_val2;
    };

14 Struct guidelines
-------

We think hiding the presence of a pointer makes the code unnecessarily
ambiguous and more difficult. 

Seeing a * in a variable declaration immediately identifies a pointer, which
is easier to mentally keep track of!

Also we think that defining the struct as a typedef makes forward declarations
clunky and find using the C++ style when declaring our structs makes our
lives easier.

    //
    // Us human parsers find this confusing.
    //
    typedef struct _my_struct
    {
      u_int16	m_field;
    } my_struct, 
    *p_my_struct;

    //
    // This is easier!
    //
    struct my_struct {
      u_int16	m_field;
    };


15 Temporary variables 
-------

Since "j" is used less frequently in english prose than "a" or "i", we find 
that these variables (in hierarchical order) are great for counters: j, k, l, 
m, n.

Example:

    int32_t j,k;
    for(j = 0; j < 10; j++)
    {
      for(k = 0; k < 10; k++)
      {
        int32_t foo = j + k;
      }
    }

as opposed to:

    int32_t i,counter;
    for(i = 0; i < 10; i++)
    {
      for(counter = 0; counter < 10; counter++)
      {
        int32_t foo = i + counter;
      }
    }

16 Error management 
-------

Error management inside libscap is done through return values, since the scap 
library is written in C.
Error management in the rest of the sysdig user level code base is done through
exceptions. We know there's a lot of debate between return values and 
exceptions. We decided to pick the latter, so please stick with that.

## You Made It!

Phew! That's it. Thanks!

If we've left anything in the open, feel free to contact us and we'll be happy
to get back to you.  Also, you can look at the existing code and see how it's
done.

Have a good one!
