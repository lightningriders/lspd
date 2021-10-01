package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"google.golang.org/grpc/metadata"
)

type copyFromEvents struct {
	events []*lnrpc.ForwardingEvent
	idx    int
	err    error
}

func (cfe *copyFromEvents) Next() bool {
	cfe.idx++
	return cfe.idx < len(cfe.events)
}

func (cfe *copyFromEvents) Values() ([]interface{}, error) {
	event := cfe.events[cfe.idx]
	values := []interface{}{
		event.TimestampNs,
		event.ChanIdIn, event.ChanIdOut,
		event.AmtInMsat, event.AmtOutMsat}
	return values, nil
}

func (cfe *copyFromEvents) Err() error {
	return cfe.err
}

func channelsSynchronize(macaroonHex string, chainClient chainrpc.ChainNotifierClient, lndClient lnrpc.LightningClient) {
	lastSync := time.Now().Add(-6 * time.Minute)
	for {
		cancellableCtx, cancel := context.WithCancel(context.Background())
		clientCtx := metadata.AppendToOutgoingContext(cancellableCtx, "macaroon", macaroonHex)
		stream, err := chainClient.RegisterBlockEpochNtfn(clientCtx, &chainrpc.BlockEpoch{})
		if err != nil {
			log.Printf("chainNotifierClient.RegisterBlockEpochNtfn(): %v", err)
			cancel()
		}

		for {
			_, err := stream.Recv()
			if err != nil {
				log.Printf("stream.Recv: %v", err)
				break
			}
			if lastSync.Add(5 * time.Minute).Before(time.Now()) {
				time.Sleep(30 * time.Second)
				err = channelsSynchronizeOnce(macaroonHex,lndClient)
				lastSync = time.Now()
				log.Printf("channelsSynchronizeOnce() err: %v", err)
			}
		}
		cancel()
	}
}

func channelsSynchronizeOnce(macaroonHex string, client lnrpc.LightningClient) error {
	log.Printf("channelsSynchronizeOnce - begin")
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", macaroonHex)
	channels, err := client.ListChannels(clientCtx, &lnrpc.ListChannelsRequest{PrivateOnly: true})
	if err != nil {
		log.Printf("ListChannels error: %v", err)
		return fmt.Errorf("client.ListChannels() error: %w", err)
	}
	log.Printf("channelsSynchronizeOnce - received channels")
	lastUpdate := time.Now()
	for _, c := range channels.Channels {
		nodeID, err := hex.DecodeString(c.RemotePubkey)
		if err != nil {
			log.Printf("hex.DecodeString in channelsSynchronizeOnce error: %v", err)
			continue
		}
		err = insertChannel(c.ChanId, c.ChannelPoint, nodeID, lastUpdate)
		if err != nil {
			log.Printf("insertChannel(%v, %v, %x) in channelsSynchronizeOnce error: %v", c.ChanId, c.ChannelPoint, nodeID, err)
			continue
		}
	}
	log.Printf("channelsSynchronizeOnce - done")

	return nil
}

func forwardingHistorySynchronize(ctx context.Context, client lnrpc.LightningClient) {
	for {
		err := forwardingHistorySynchronizeOnce(ctx,client)
		log.Printf("forwardingHistorySynchronizeOnce() err: %v", err)
		time.Sleep(1 * time.Minute)
	}
}

func forwardingHistorySynchronizeOnce(ctx context.Context, client lnrpc.LightningClient) error {
	last, err := lastForwardingEvent()
	if err != nil {
		return fmt.Errorf("lastForwardingEvent() error: %w", err)
	}
	log.Printf("last1: %v", last)
	last = last/1_000_000_000 - 1*3600
	if last <= 0 {
		last = 1
	}
	log.Printf("last2: %v", last)
	now := time.Now()
	endTime := uint64(now.Add(time.Hour * 24).Unix())
	indexOffset := uint32(0)
	for {
		forwardHistory, err := client.ForwardingHistory(ctx, &lnrpc.ForwardingHistoryRequest{
			StartTime:    uint64(last),
			EndTime:      endTime,
			NumMaxEvents: 10000,
			IndexOffset:  indexOffset,
		})
		if err != nil {
			log.Printf("ForwardingHistory error: %v", err)
			return fmt.Errorf("client.ForwardingHistory() error: %w", err)
		}
		log.Printf("Offset: %v, Events: %v", indexOffset, len(forwardHistory.ForwardingEvents))
		if len(forwardHistory.ForwardingEvents) == 0 {
			break
		}
		indexOffset = forwardHistory.LastOffsetIndex
		cfe := copyFromEvents{events: forwardHistory.ForwardingEvents, idx: -1}
		err = insertForwardingEvents(&cfe)
		if err != nil {
			log.Printf("insertForwardingEvents() error: %v", err)
			return fmt.Errorf("insertForwardingEvents() error: %w", err)
		}
	}
	return nil
}
