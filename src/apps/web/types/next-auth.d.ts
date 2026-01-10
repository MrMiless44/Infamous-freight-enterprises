declare module "next-auth/react" {
  export const getSession: any;
  export const useSession: any;
  export const signIn: any;
  export const signOut: any;
}

declare module "next-auth" {
  export const NextAuth: any;
}
