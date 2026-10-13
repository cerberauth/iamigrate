FROM node:22-slim

# The Auth emulator is part of firebase-tools and needs no Java (only the
# Firestore/Storage emulators do).
RUN npm install --global --no-audit --no-fund firebase-tools@15.33.0

WORKDIR /srv
COPY firebase.json .

EXPOSE 9099
CMD ["firebase", "emulators:start", "--only", "auth", "--project", "demo-iamigrate"]
