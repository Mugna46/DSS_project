#import "@preview/wrap-it:0.1.0": wrap-content
#import "frontpage.typ": report

#show: doc => report(
  title: "Malware Analysis",
  subtitle: "for the DSS course",
  authors: "Andrea Mugnai, Jacopo Tucci",
  date: "2024/2025",
  doc,
  imagepath: "marchio_unipi_black.svg"
)

// Code block style
#show raw.where(block: true): block.with(
  fill: luma(240),
  inset: 10pt,
  radius: 10pt,
)

#let makesubparagraph(title) = heading(numbering: none, outlined: false, level: 4)[#title]



= Introduction
The purpose of this report is to provide a comprehensive analysis of the malware using different tools and techniques. The analysis will cover the following aspects:
#v(0.5em)
- Static analysis
- Dynamic analysis

#linebreak()
The main goal was to identify the malicious payload inside the `APK` files of the provided samples.

#linebreak()

== Tools used

#linebreak()



