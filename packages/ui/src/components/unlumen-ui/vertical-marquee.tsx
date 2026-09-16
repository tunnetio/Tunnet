"use client";
import { getTweet, type Tweet } from "react-tweet/api";

import {
  TweetNotFound,
  VerticalMarqueeClient,
} from "./vertical-marquee-client";
import type { TweetItem } from "./vertical-marquee.types";

export type { TweetItem } from "./vertical-marquee.types";

export interface VerticalMarqueeProps {
  /** Tweet IDs to display in the scrolling columns. */
  tweetIds: string[];
  /** Number of scrolling columns. @default 2 */
  columns?: 1 | 2;
  /** Scroll duration in seconds per full loop. @default 20 */
  speed?: number;
  /** Vertical gap between cards in px. @default 16 */
  gap?: number;
  /** Height of the fade zone at top and bottom in px. @default 120 */
  blurSize?: number;
  /** Smoothly decelerate to a stop when hovering. @default true */
  pauseOnHover?: boolean;
  className?: string;
  tweetClassName?: string;
}

async function getTweetItem(id: string): Promise<TweetItem> {
  const tweet = await getTweet(id).catch((error) => {
    console.error(error);
    return undefined;
  });

  return { id, tweet };
}

export async function VerticalMarquee({
  tweetIds,
  columns = 2,
  speed = 20,
  gap = 16,
  blurSize = 120,
  pauseOnHover = true,
  className,
  tweetClassName,
}: VerticalMarqueeProps) {
  if (!tweetIds.length) {
    return null;
  }

  const tweets = await Promise.all(tweetIds.map((id) => getTweetItem(id)));
  const hasResolvedTweet = tweets.some((item) => item.tweet);

  if (!hasResolvedTweet) {
    return (
      <div className="grid gap-4 sm:grid-cols-2">
        {tweetIds.slice(0, Math.min(tweetIds.length, 4)).map((id) => (
          <TweetNotFound key={id} />
        ))}
      </div>
    );
  }

  return (
    <VerticalMarqueeClient
      tweets={tweets}
      columns={columns}
      speed={speed}
      gap={gap}
      blurSize={blurSize}
      pauseOnHover={pauseOnHover}
      className={className}
      tweetClassName={tweetClassName}
    />
  );
}

export {
  MagicTweet,
  TweetBody,
  TweetHeader,
  TweetMedia,
  TweetNotFound,
  TweetSkeleton,
  VerticalMarqueeClient,
} from "./vertical-marquee-client";
