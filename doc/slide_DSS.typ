#import "@preview/touying:0.5.5": *
#import themes.university: * // https://touying-typ.github.io/docs/themes/university/

#import "@preview/cetz:0.3.2"

#let vimg(body) = {
    rect(width: 10mm, height: 5mm)[
        #text(body)
    ]
}

#show: university-theme.with(
  aspect-ratio: "16-9",
  config-info(
    title: [
      #figure(
        image("/img/marchio_unipi_black.svg", width: 40%),
      )
      ],
    subtitle: [Dependability and Secure System 2025],
    author: ([Andrea Mugnai], [], [Jacopo Tucci], []),
    institution: [University of Pisa],
  ),
  config-common(handout: false),
  footer-a: [A.M. J.T.]
)

#title-slide(logo: image("/img/marchio_unipi_black.svg", width: 12%))

= Introduction

== Static Analysis
#slide[
  #v(1em)
  #figure(
    grid(
        columns: 2,     // 2 means 2 auto-sized columns
        gutter: 15mm,    // space between columns
        image("/img/mobsf_logo.png", width: 80%),
        image("/img/VirusTotal_logo.png", width: 100%),
    ),
)
#set align(center)
Starting from VirusTotal analysis and integrating it with MobSF we classified our samples as:
#v(0.3em)
- *FakeBank* (4 samples)
- *Locker* (1 sample)
The initial classification made by those tools was subsequently verified by analyzing the source code of the APKs decompiled using *JD-GUI*.
]

== Dynamic Analysis
#slide[
  #v(0.5em)
  #set align(center)
  #set text(size: 22pt)
  The dynamic analysis was performed using the *Android Emulator* provided by *Android Studio*. Simulating a Pixel XL device with *Android 9.0* (API level 28), we installed and executed the APKs using the *MobSF Dynamic Analysis* tool in a *Virtual Machine*.  
  #v(1em)
  #figure(
    grid(
        columns: 2,     // 2 means 2 auto-sized columns
        gutter: 15mm,    // space between columns
        image("/img/android_studio_logo.jpeg", width: 60%),
        image("/img/android-9-pie.png", width: 120%),
    ),
)
]

= Fakebank Family

#slide[
  #figure(
    grid(
        columns: 2,     // 2 means 2 auto-sized columns
        gutter: 5mm,    // space between columns
        image("/img/ibk_icon.png", width: 30%),
        image("/img/ibk_icon.png", width: 30%),
        image("/img/example_icon.png", width: 30%),
        image("/img/xinhan_icon.png", width: 30%),
    ),
)
#v(1em)
#set align(center)
The four analyzed *Malware* samples are *Trojan bankers* designed to mimic legitimate banking apps. In reality, they steal sensitive user information such as phone numbers and banking credentials. Additionally, they intercept all incoming SMS messages to capture one-time passwords `(OTPs)` sent by the bank.
]

== Permissions
#slide[
  #figure(
    grid(
        columns: 2,     // 2 means 2 auto-sized columns
        gutter: 5mm,   // space between columns
        image("/img/Permission_fakebank.png", width: 85%),
        grid(
        columns: 1,     // 1 means 1 auto-sized column
        rows: 2,     // 2 means 2 auto-sized rows
        rect(stroke: none)[
            #set align(left)
            #set text(size: 20pt)
            The most dangerous permissions used by the malware are those related to managing SMS messages and phone calls. Combined with the #strong[broadcasting] permission and by assigning the app the highest priority (*1000*), the malware is able to intercept all incoming SMS messages and phone calls.
        ],
        image("/img/Manifest_fakebank.png", width: 120%, height: 50%, fit: "contain"),
        ),
      ),
  )
]
== App Flow
#slide[
  #v(1em)
  #figure(
    image("/img/diagram_fakebank.drawio.png")
  )
  #set text(size: 20pt)
  #set align(center)
  `BankSplashActivity` and `BankEndActivity` sends all the stolen data to a remote server that is not the legitimate one. (`http://banking1.kakatt.net:9998`) 
]
        