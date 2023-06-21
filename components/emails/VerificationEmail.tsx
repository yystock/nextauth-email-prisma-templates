import React from "react";
import { Body, Container, Head, Tailwind, Heading, Html, Img, Link, Text, Button } from "@react-email/components";

interface VerificationEmailProps {
  token: string;
}

const baseUrl = process.env.BASE_URL ? `https://${process.env.BASE_URL}` : "";

export const VerificationEmail = ({ token }: VerificationEmailProps) => (
  <Html>
    <Head />
    <Tailwind>
      <Body className="mx-auto bg-white font-sans">
        <Container className="rounded-lg  p-8 shadow-lg">
          <Heading className="pt-4 text-xl">🫶 Hello There 🫶</Heading>
          <Text className="text-lg font-medium text-gray-700 ">
            Thanks for Joining this community. Click the link below to activate your account.
          </Text>
          <Button href={`${baseUrl}/api/email/${token}`} className="rounded-md bg-purple-700 px-4 py-6 font-bold text-white">
            Activate Account
          </Button>
        </Container>
      </Body>
    </Tailwind>
  </Html>
);

export default VerificationEmail;
