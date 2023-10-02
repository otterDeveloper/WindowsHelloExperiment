# Windows Hello Experiment

This is a Windows Forms dotnet7 project I created for experimenting with Windows Hello and Fido2 / WebAuthn.

## WindowsHellosExperiment

Is the project that contains the Windows Forms application.

## WindowsHelloAPI

Contains the dotnet bindings for the webauthn.dll based on the [header files provided by Microsoft](https://github.com/microsoft/webauthn).

ChatGPT did the heavy lifting of creating the bindings, but it didn't cut, so I had to some manual polishing.

## WindowsHelloHelper

Was an attempt to create a wrapper around the webauthn.dll using cppSharp. It is not used in the project.